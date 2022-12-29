#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<thread>
#include <iostream>
#include <cmath>
#include <wiringPi.h>
#include "agent.h"

#define MAXLINE 4096
#define STATE_FACTOR 100000000
#define BUFSIZE 2048
#define KEY_LENGTH 256
#define SEND_TIME_INTERVAL 1

const int maxSteps = 1000;
using namespace std;


void receiveMsg(int connfd);
void listenAccept(int listenfd);
int initListedfd(int port,char *ipaddr);
void initNeighbor();
int initNeighborSocketfdAndServaddr();
void connectWithNeighbors();
void sendMessageToAll(char sendline[],int size);
long long ciphertext_to_long(paillier_ciphertext_t *c, paillier_pubkey_t *pubKey, paillier_prvkey_t *prvKey);
void sendEncryptedToAllForOneTime();
void sendEncryptedIntegerMsgToAllNeighborsWithMaxSteps();
void receiveEncryptedState(int connfd);
void initFourNeighbors();
void initTwoNeighbors();
void sendMessageToOne(char sendline[],int size,char receiver);
void initLocalNeighbor();
void lightBlink();


struct myNeighbor {
    int port;
    char name;
    int sockfd;
    int step = 0;
    double state = 0;
    double state_Y = 0;
    double state_Z = 0;
    double diff = 0.0;
    double diff_Y = 0.0;
    double diff_Z = 0.0;
    double input = 0.0;
    struct sockaddr_in servaddr;
    char ipaddr[100];
};

myNeighbor neighborVector[10];
vector<int> connfdVector;
double agentCount;
int myClientIndex;
char myIpaddr[100];
int myPort;
char myName;
double myInput;
vector<int> trueNeighbors;


Agent *me = new Agent();


int main(int argc, char** argv){
    int sockfd;
    struct sockaddr_in  servaddr;
    setbuf(stdout,NULL);


    //init ipAdress and port for neighbors and current client
    agentCount = atoi(argv[1]);
    myClientIndex = atoi(argv[2]);
    me->setAgentId(myClientIndex);
    initNeighbor();
    if (agentCount==4){
        initFourNeighbors();
    }
    if (agentCount==2){
        initTwoNeighbors();
    }
    strcpy(myIpaddr,neighborVector[myClientIndex].ipaddr);
    myPort = neighborVector[myClientIndex].port;
    myName = neighborVector[myClientIndex].name;
    myInput = neighborVector[myClientIndex].input;
    thread bliknThread(lightBlink);
    bliknThread.detach();

    //enable server and receive message
    int listenfd = initListedfd(myPort,myIpaddr);
    if (listenfd==0){
        cout<<"warning:bind socket error: Address already in use(errno: 98)"<<endl;
        return 0;
    }
    me->print_K_OF_KWTA();
    cout<<"SEND_TIME_INTERVAL: "<<SEND_TIME_INTERVAL<<endl;
    cout<<"VERSION: 2022年10月14日23:01:26"<<endl;
    printf("======waiting for client's request at ip adress: %s, port: %d======\n",myIpaddr,myPort);
    thread listenThread(listenAccept,listenfd);
    listenThread.detach();

    initNeighborSocketfdAndServaddr();
    connectWithNeighbors();


//    char fileName[70]="";
//    sprintf(fileName,"input:%.2lf:%.2lf:%.2lf:%.2lf_client%d.txt",neighborVector[0].input,neighborVector[1].input,neighborVector[2].input,neighborVector[3].input,myClientIndex);

    me->setState(myInput,agentCount,neighborVector[myClientIndex].state,neighborVector[myClientIndex].state_Y);
//    me->setState(neighborVector[myClientIndex].state,neighborVector[myClientIndex].state_Y,neighborVector[myClientIndex].state_Z);

    //此处注意要休眠一秒钟，否则会出现最后一个agent无法接收消息的BUG
    //原因如下
    //4个agent逐个启动最后一个启动的agent会瞬间完成connectWithNeighbors函数
    //但此时另一个线程listenThread尚未将接收到的连接同步到connfdVector中，此处connfdVector的大小为0，直接遍历无法获取数据
    sleep(1);
    cout<<"connfdVector.size: "<<connfdVector.size()<<endl;
    for (int i = 0; i < connfdVector.size(); ++i) {
        thread t1(receiveEncryptedState,connfdVector[i]);
        t1.detach();
    }


    //new way to enable client and send message
    sendEncryptedIntegerMsgToAllNeighborsWithMaxSteps();
    while (1){
        sleep(10);
    }
    return 0;
}





void sendEncryptedToAllForOneTime(){
    /**
     * create encrypted text
     */
    me->long_state = -(long long) llround(me->state * STATE_FACTOR);
    me->long_state_Y = -(long long) llround(me->state_Y * STATE_FACTOR);
    me->long_state_Z = -(long long) llround(me->state_Z * STATE_FACTOR);
    paillier_plaintext_t *m_s = paillier_plaintext_from_ui(me->long_state);
    paillier_plaintext_t *m_s_Y = paillier_plaintext_from_ui(me->long_state_Y);
    paillier_plaintext_t *m_s_Z = paillier_plaintext_from_ui(me->long_state_Z);
    paillier_ciphertext_t *c_s = NULL;
    paillier_ciphertext_t *c_s_Y = NULL;
    paillier_ciphertext_t *c_s_Z = NULL;
    c_s = paillier_enc(NULL, me->pubKey, m_s,
                       paillier_get_rand_devurandom);
    c_s_Y = paillier_enc(NULL, me->pubKey, m_s_Y,
                         paillier_get_rand_devurandom);
    c_s_Z = paillier_enc(NULL, me->pubKey, m_s_Z,
                         paillier_get_rand_devurandom);
    char *hexPubKey = paillier_pubkey_to_hex(me->pubKey); //serialize pub key
    char *byteCtxt = (char *) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2,c_s);//serialize cypher
    char *byteCtxt_Y = (char *) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2,c_s_Y);//serialize cypher
    char *byteCtxt_Z = (char *) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2,c_s_Z);//serialize cypher
    int s_pub = strlen(hexPubKey);




//    char *hexPriKey = paillier_prvkey_to_hex(me->prvKey);
//    int s_pri = strlen(hexPriKey);            //等下继续加传私钥代码




    int s_ctxt = PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2;
    int i = 0;
    char type = '1';


    /**
     * convert encrypted text to sendBuf
     */
    char sendBuf[BUFSIZE];
    memcpy(&sendBuf[i], &type, sizeof(char));
    i += sizeof(char); //add type
    int step = me->step;
    memcpy(&sendBuf[i], &step, sizeof(int));
    i += sizeof(int); //add step index;
    memcpy(&sendBuf[i], &myName, sizeof(char));
    i += sizeof(char); //add type
    memcpy(&sendBuf[i], &s_pub, sizeof(int));
    i += sizeof(int); //add size of public key




//    memcpy(&sendBuf[i], &s_pri, sizeof(int));
//    i += sizeof(int); //add size of private key




    memcpy(&sendBuf[i], &s_ctxt, sizeof(int));
    i += sizeof(int); //add size of cypher text
    strcpy(&sendBuf[i], hexPubKey);
    i += s_pub;





//    strcpy(&sendBuf[i], hexPriKey);
//    i += s_pri;





    for (int k = i; k < i + s_ctxt; k++) {
        sendBuf[k] = byteCtxt[k - i];
    }
    i += s_ctxt;
    for (int k = i; k < i + s_ctxt; k++) {
        sendBuf[k] = byteCtxt_Y[k - i];
    }
    i += s_ctxt;
    for (int k = i; k < i + s_ctxt; k++) {
        sendBuf[k] = byteCtxt_Z[k - i];
    }
    i += s_ctxt;
    sendMessageToAll(sendBuf,i);
}



void receiveEncryptedState(int connfd){
    char  buff[4096];
    while(1){
        int n = recv(connfd, buff, MAXLINE, 0);
        if(n==0){
            printf("failed\n");
            sleep(0.1);
            continue;
        }
        int i = 0;
        char type=0;
        int step;
        char srcName;
        int s_pub;




//        int s_pri;





        int s_ctxt;
        char hexPubKey[BUFSIZE];
        bzero(hexPubKey,BUFSIZE);




//        char hexPriKey[BUFSIZE];
//        bzero(hexPriKey, BUFSIZE);





        char byteCtxt[BUFSIZE];
        char byteCtxt_Y[BUFSIZE];
        char byteCtxt_Z[BUFSIZE];
        bzero(byteCtxt,BUFSIZE);
        paillier_pubkey_t *_pubKey;




//        paillier_prvkey_t *_priKey;




        paillier_ciphertext_t *ctxt;
        paillier_ciphertext_t *ctxt_Y;
        paillier_ciphertext_t *ctxt_Z;
        paillier_ciphertext_t *c_res = paillier_create_enc_zero();
        paillier_ciphertext_t *c_res_Y = paillier_create_enc_zero();
        paillier_ciphertext_t *c_res_Z = paillier_create_enc_zero();

        memcpy(&type,&buff[i],sizeof(char));
        i+= sizeof(char);
        memcpy(&step,&buff[i],sizeof(int));
        i += sizeof(int);
        memcpy(&srcName,&buff[i],sizeof(char));
        i += sizeof (char);




//        printf("receive message, type: %c,  step: %d,  srcName: %c\n",type,step,srcName);





        if (type=='1'){
            /**
             * receive message and analysis
             */
            memcpy(&s_pub,&buff[i],sizeof(int));
            i += sizeof (int);





//            memcpy(&s_pri,&buff[i],sizeof(int));
//            i += sizeof (int);






            memcpy(&s_ctxt,&buff[i],sizeof(int));
            i += sizeof (int);
            memcpy(&hexPubKey,&buff[i],s_pub);
            i += s_pub;




//            memcpy(&hexPriKey, &buff[i], s_pri);
//            i += s_pri; //read private key




            for (int k = i; k < i+s_ctxt; ++k) {
                byteCtxt[k-i] = buff[k];
            }
            i += s_ctxt;
            for (int k = i; k < i+s_ctxt; ++k) {
                byteCtxt_Y[k-i] = buff[k];
            }
            i += s_ctxt;
            for (int k = i; k < i+s_ctxt; ++k) {
                byteCtxt_Z[k-i] = buff[k];
            }
            i += s_ctxt;
            _pubKey = paillier_pubkey_from_hex(hexPubKey);





//            _priKey = paillier_prvkey_from_hex(hexPriKey, _pubKey);




            ctxt = paillier_ciphertext_from_bytes((void *) byteCtxt, PAILLIER_BITS_TO_BYTES(_pubKey->bits) *2); //recreate cypher text
            ctxt_Y = paillier_ciphertext_from_bytes((void *) byteCtxt_Y, PAILLIER_BITS_TO_BYTES(_pubKey->bits) *2);
            ctxt_Z = paillier_ciphertext_from_bytes((void *) byteCtxt_Z, PAILLIER_BITS_TO_BYTES(_pubKey->bits) *2);





//            long long longCtxtX = ciphertext_to_long(ctxt,_pubKey,_priKey);
//            long long longCtxtY = ciphertext_to_long(ctxt_Y,_pubKey,_priKey);
//            long long longCtxtZ = ciphertext_to_long(ctxt_Z,_pubKey,_priKey);
//            cout<<"longCtxtX: "<<longCtxtX<<"  ,longCtxtY: "<<longCtxtY<<"  ,longCtxtZ: "<<longCtxtZ<<endl;




            if (step<=me->step){
                /**
                 * create encrtpted ACK after receive
                 */
                me->exchange(_pubKey, ctxt, ctxt_Y,ctxt_Z,c_res, c_res_Y,c_res_Z,step);




//                long long longCresX = ciphertext_to_long(c_res,_pubKey,_priKey);
//                long long longCresY = ciphertext_to_long(c_res_Y,_pubKey,_priKey);
//                long long longCresZ = ciphertext_to_long(c_res_Z,_pubKey,_priKey);
//                cout<<"longCresX: "<<longCresX<<"  ,longCresY: "<<longCresY<<"  ,longCresZ: "<<longCresZ<<endl;





                char *resBytes = (char *) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(_pubKey->bits) * 2,c_res);
                int size = PAILLIER_BITS_TO_BYTES(_pubKey->bits) * 2;
                char *resBytes_Y = (char *) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(_pubKey->bits) * 2,c_res_Y);
                char *resBytes_Z = (char *) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(_pubKey->bits) * 2,c_res_Z);
                /**
                 * return encrtpted ACK after create
                 */
                int i = 0;
                type = '2';
                char respBuf[BUFSIZE];
                bzero(respBuf,BUFSIZE);
                memcpy(&respBuf[i],&type,sizeof(char));
                i+=sizeof (char);
                memcpy(&respBuf[i],&step,sizeof(int));
                i+=sizeof (int);
                memcpy(&respBuf[i],&myName,sizeof (char));
                i+= sizeof (char);
                memcpy(&respBuf[i],&size, sizeof(int));
                i+= sizeof(int);
                for (int k = i; k < (i + size); k++) {
                    respBuf[k] = resBytes[k - i];
                }
                i += size;
                for (int k = i; k < (i + size); k++) {
                    respBuf[k] = resBytes_Y[k - i];
                }
                i += size;
                for (int k = i; k < (i + size); k++) {
                    respBuf[k] = resBytes_Z[k - i];
                }
                i += size;
                //lcbComment //sendData(respBuf, j, respAddr);
                sendMessageToOne(respBuf,i,srcName);
//                cout << "Sending response" << endl;
                paillier_freeciphertext(c_res);
            }
        } else if (type=='2'){
            //明天早上从这里开始写消息类型2的处理代码
            //参考communcation.h代码中的消息类型2处理代码写法
            memcpy(&s_ctxt,&buff[i], sizeof(int));
            i += sizeof(int);
            for (int k = i; k < (i+s_ctxt); ++k) {
                byteCtxt[k-i] = buff[k];
            }
            i+=s_ctxt;
            for (int k = i; k < (i+s_ctxt); ++k) {
                byteCtxt_Y[k-i] = buff[k];
            }
            i+=s_ctxt;
            for (int k = i; k < (i+s_ctxt); ++k) {
                byteCtxt_Z[k-i] = buff[k];
            }
            i+=s_ctxt;
            ctxt = paillier_ciphertext_from_bytes((void *) byteCtxt,PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2); //recreate
            ctxt_Y = paillier_ciphertext_from_bytes((void *) byteCtxt_Y,PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2);
            ctxt_Z = paillier_ciphertext_from_bytes((void *) byteCtxt_Z,PAILLIER_BITS_TO_BYTES(me->pubKey->bits) * 2);
            long long result = 0;
            long long result_Y = 0;
            long long result_Z = 0;
            int cont = 1;
//            me->diff_state = 0;
            long long diff_state = 0;
            long long diff_state_Y = 0;
            long long diff_state_Z = 0;
            result = me->ciphertext_to_long(ctxt);
            result_Y = me->ciphertext_to_long(ctxt_Y);
            result_Z = me->ciphertext_to_long(ctxt_Z);
//            cout<<"result_X: "<<result<<"   ,result_Y: "<<result_Y<<"  ,result_Z:"<<result_Z<<endl;

            int index = -1;
            for (int j = 0; j < agentCount; ++j) {
                if (j!=myClientIndex&&neighborVector[j].name==srcName){
                    index = j;
                    break;
                }
            }

            if (index!=-1&&me->_myVector[index].step < step) {
                neighborVector[index].diff = me->_alphas[step - 1] * result;
                neighborVector[index].diff_Y = me->_alphas[step - 1] * result_Y;
                neighborVector[index].diff_Z = me->_alphas[step - 1] * result_Z;
                neighborVector[index].step = step;

                //compare all neighbors are at the same step
                for (int j = 0; j < trueNeighbors.size(); ++j) {
                    int c = trueNeighbors[j];
                    if (neighborVector[c].step == step) {
                        cont *= 1;
                    } else {
                        cont *= 0;
                    }
                }

                //cout<<"contd: "<<cont<<endl;

                if (cont) {
                    for (int j = 0; j < trueNeighbors.size(); ++j) {
                        int c = trueNeighbors[j];
//                        cout<<"before diff_state_X: "<<diff_state<<"  ,Y: "<<diff_state_Y<<"  Z:"<<diff_state_Z<<endl;
//                        cout<<"neighborVector["<<c<<"].diff_X:"<<neighborVector[c].diff<<"  ,diff_Y:"<<neighborVector[c].diff_Y<<"  ,diff_Z:"<<neighborVector[c].diff_Z<<endl;
                        diff_state += neighborVector[c].diff;
                        diff_state_Y += neighborVector[c].diff_Y;
                        diff_state_Z += neighborVector[c].diff_Z;
//                        cout<<"After diff_state_X: "<<diff_state<<"  ,Y: "<<diff_state_Y<<"  Z:"<<diff_state_Z<<endl;
                    }
//                    cout<<"Diff state"<<me->diff_state<<endl;
//                    cout<<"updating state"<<endl;
                    me->updateState(diff_state,diff_state_Y,diff_state_Z);
                }

            }
        }

        bzero(buff,n+1);
//        close(connfd);
    }
}

void sendEncryptedIntegerMsgToAllNeighborsWithMaxSteps(){
    printf("send encrypted msg to server: \n");
    for(int n=0;n<maxSteps;n++){
//        printf("Step : %d", n);
        sendEncryptedToAllForOneTime();
//        cout << "   My state is: " << me->state << endl;
        //注意此处一定要休眠一秒，不休眠或之休眠0.1秒都会报不知名的错误
        //以上不知名错误的原因一发现，因为sleep方法只能接受秒级单位的整数参数，但单位为0.X的小数时会被转换成0，即不休眠
        sleep(1);
//        usleep(1000000);
//        this_thread::sleep_for(chrono::milliseconds(300));
    }
    fclose(me->fp);
}



int initNeighborSocketfdAndServaddr(){
    for (int i = 0; i < agentCount; ++i) {
        if (i!=myClientIndex){
            if( (neighborVector[i].sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
                printf("init sockfd at Index %d, create socket error: %s(errno: %d)\n", i,strerror(errno),errno);
                return 0;
            }
            memset(&neighborVector[i].servaddr, 0, sizeof(neighborVector[i].servaddr));
            neighborVector[i].servaddr.sin_family = AF_INET;
            neighborVector[i].servaddr.sin_port = htons(neighborVector[i].port);
            if( inet_pton(AF_INET, neighborVector[i].ipaddr, &neighborVector[i].servaddr.sin_addr) <= 0){
                printf("inet_pton error for %s\n",neighborVector[i].ipaddr);
                return 0;
            }
        }
    }
}


void sendMessageToAll(char sendline[],int size){
    for (int j = 0; j < trueNeighbors.size(); ++j) {
        int i = trueNeighbors[j];
        if( send(neighborVector[i].sockfd, sendline, size, 0) < 0){
            printf("111send msg error: %s(errno: %d)\n", strerror(errno), errno);
            printf("connect to server again.\n");
            if( connect(neighborVector[i].sockfd, (struct sockaddr*)&neighborVector[i].servaddr, sizeof(neighborVector[i].servaddr)) < 0){
                printf("111reconnect error: %s(errno: %d)\n",strerror(errno),errno);
                continue;
            }
            continue;
        }
//            sleep(0.01);
    }
}

void sendMessageToOne(char sendline[],int size,char receiver){
    for (int i = 0; i < agentCount; ++i) {
        if (receiver==neighborVector[i].name){
            if( send(neighborVector[i].sockfd, sendline, size, 0) < 0){
                printf("222send msg error: %s(errno: %d)\n", strerror(errno), errno);
                printf("connect to server again.\n");
                if( connect(neighborVector[i].sockfd, (struct sockaddr*)&neighborVector[i].servaddr, sizeof(neighborVector[i].servaddr)) < 0){
                    printf("222reconnect error: %s(errno: %d)\n",strerror(errno),errno);
                    continue;
                }
                continue;
            }
        }
    }
}



int initListedfd(int port,char *ipaddr){
    int  listenfd;
    struct sockaddr_in  servaddr;
    if( (listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
        printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
        return 0;
    }
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ipaddr);
    servaddr.sin_port = htons(port);
    int opt = 1;
    setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,(const void *)&opt,sizeof(opt));
    if( bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);
        return 0;
    }
    if( listen(listenfd, 10) == -1){
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);
        return 0;
    }
    return listenfd;
}


void listenAccept(int listenfd){
    int connfd;
    while (1){
        if( (connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
        }
        connfdVector.push_back(connfd);
        cout<<"connect from : "<<connfd<<endl;
//        thread t1(receiveEncryptedState,connfd);
//        t1.detach();
    }
    close(listenfd);
}


void connectWithNeighbors(){
    while (1){
        bool check = true;
        for (int j = 0; j < trueNeighbors.size(); ++j) {
            int i = trueNeighbors[j];
            int coonectResult = connect(neighborVector[i].sockfd, (struct sockaddr*)&neighborVector[i].servaddr, sizeof(neighborVector[i].servaddr));
            if( coonectResult < 0&&errno==111){
                printf("connect with agent (%d) error: %s(errno: %d)\n",i,strerror(errno),errno);
                check = false;
            }
        }
        if (check){
            sleep(1);
            return;
        }
        sleep(1);
    }
}


void initNeighbor(){
    strcpy(neighborVector[0].ipaddr,"192.168.137.192");
    neighborVector[0].port=6666;
    neighborVector[0].name = 'a';
//    neighborVector[0].state = 200;
//    neighborVector[0].state_Y = 300;
    neighborVector[0].state = 0.6294;
    neighborVector[0].state_Y = 55;
    neighborVector[0].state_Z = 400;
    neighborVector[0].input = 1.1;


    strcpy(neighborVector[1].ipaddr,"192.168.137.152");
    neighborVector[1].port=6674;
    neighborVector[1].name = 'b';
//    neighborVector[1].state = 300;
//    neighborVector[1].state_Y = 400;
    neighborVector[1].state = 0.8116;
    neighborVector[1].state_Y = 68;
    neighborVector[1].state_Z = 500;
    neighborVector[1].input = 2.5;

    strcpy(neighborVector[2].ipaddr,"192.168.137.32");
    neighborVector[2].port=6675;
    neighborVector[2].name = 'c';
//    neighborVector[2].state = 100;
//    neighborVector[2].state_Y = 200;
    neighborVector[2].state = -0.7460;
    neighborVector[2].state_Y = 35;
    neighborVector[2].state_Z = 300;
    neighborVector[2].input = 4;

    strcpy(neighborVector[3].ipaddr,"192.168.137.31");
    neighborVector[3].port=6676;
    neighborVector[3].name = 'd';
//    neighborVector[3].state = 600;
//    neighborVector[3].state_Y = 700;
    neighborVector[3].state = 0.8268;
    neighborVector[3].state_Y = 79;
    neighborVector[3].state_Z = 800;
    neighborVector[3].input = 3.2;
}


void initLocalNeighbor(){
    strcpy(neighborVector[0].ipaddr,"127.0.0.1");
    neighborVector[0].port=6666;
    neighborVector[0].name = 'a';
//    neighborVector[0].state = 200;
//    neighborVector[0].state_Y = 300;
    neighborVector[0].state = 0.6294;
    neighborVector[0].state_Y = 55;
    neighborVector[0].state_Z = 400;
    neighborVector[0].input = 1.1;


    strcpy(neighborVector[1].ipaddr,"127.0.0.1");
    neighborVector[1].port=6674;
    neighborVector[1].name = 'b';
//    neighborVector[1].state = 300;
//    neighborVector[1].state_Y = 400;
    neighborVector[1].state = 0.8116;
    neighborVector[1].state_Y = 68;
    neighborVector[1].state_Z = 500;
    neighborVector[1].input = 2.5;

    strcpy(neighborVector[2].ipaddr,"127.0.0.1");
    neighborVector[2].port=6675;
    neighborVector[2].name = 'c';
//    neighborVector[2].state = 100;
//    neighborVector[2].state_Y = 200;
    neighborVector[2].state = -0.7460;
    neighborVector[2].state_Y = 35;
    neighborVector[2].state_Z = 300;
    neighborVector[2].input = 4;

    strcpy(neighborVector[3].ipaddr,"127.0.0.1");
    neighborVector[3].port=6676;
    neighborVector[3].name = 'd';
//    neighborVector[3].state = 600;
//    neighborVector[3].state_Y = 700;
    neighborVector[3].state = 0.8268;
    neighborVector[3].state_Y = 79;
    neighborVector[3].state_Z = 800;
    neighborVector[3].input = 3.2;
}


void initFourNeighbors(){
    if (myClientIndex==0){
        trueNeighbors.push_back(1);
    }
    if (myClientIndex==1){
        trueNeighbors.push_back(0);
        trueNeighbors.push_back(2);
    }
    if (myClientIndex==2){
        trueNeighbors.push_back(1);
        trueNeighbors.push_back(3);
    }
    if (myClientIndex==3){
        trueNeighbors.push_back(2);
    }
}

void initTwoNeighbors(){
    if (myClientIndex==0){
        trueNeighbors.push_back(1);
    }
    if (myClientIndex==1){
        trueNeighbors.push_back(0);
    }
}


long long ciphertext_to_long(paillier_ciphertext_t *c, paillier_pubkey_t *pubKey, paillier_prvkey_t *prvKey) {
    paillier_plaintext_t *m = paillier_dec(NULL, pubKey, prvKey, c);

    size_t nBytes = 0;
    unsigned char *bytes = (unsigned char *) mpz_export(0, &nBytes, 1, 1, 0, 0, m->m);

    long int e = 0;
    //如果是在32位系统下运行，此处变量e的类型要给为int，否则转换负数时会出错
//    int e = 0;
    //  assert( nBytes > sizeof(a));
    //  for(int i=nBytes-1; i >= nBytes-sizeof(a); --i)
//    for (int i = nBytes - sizeof(long); i < nBytes; i++) {
//        e = (e << 8) | bytes[i];
//    }
    for (int i = 0; i < nBytes; i++) {
        e = (e << 8) | bytes[i];
    }

    paillier_freeplaintext(m);
    free(bytes);
    return e;
}


void lightBlink(){
    wiringPiSetup () ;
    pinMode (29, OUTPUT) ;
    for (;;)
    {
        sleep(0.2);
        if (me->step>900&&(abs(me->state_Z-1.0))<0.001){
            digitalWrite (29, HIGH) ; delay (500) ;
//            digitalWrite (29,  LOW) ; delay (500) ;
            continue;
        }
        digitalWrite (29,  LOW) ;
    }
}