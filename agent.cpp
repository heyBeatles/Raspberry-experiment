/*
	Agent.cpp
*/
#include <math.h>
#include "agent.h"
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#include <unistd.h>

#define KEY_LENGTH 256
#define STATE_FACTOR 100000000
#define ALPHA_FACTOR 100
#define BUFSIZE 2048
#define K_OF_KWTA 2.0
#define ALPHA_OF_G 0.1
using namespace std;

//int bb;

Agent::Agent()
        : state(0.0),
          state_Y(0.0),
          state_Z(0.0),
          alpha(1),
          long_state(0),
          long_state_Y(0),
          long_state_Z(0),
          diff_state(0),
          diff_state_Y(0),
          diff_state_Z(0){
    // Generate key pair
    paillier_keygen(KEY_LENGTH,
                    &pubKey,
                    &prvKey,
                    paillier_get_rand_devurandom);
//    fp = fopen("plot.dat", "w+");
    // Open the log file:
    alpha = rand() % ALPHA_FACTOR + 1;
}

Agent::~Agent() {
    // Close the log file
    if (logfile != NULL)
        fclose(logfile);

    // Destroy the key pair
    paillier_freepubkey(pubKey);
    paillier_freeprvkey(prvKey);
}

void Agent::setAgentId(int _agentId){
     agentId = _agentId;
}


double Agent::setState(double x,double y,double z) {
    state = x;
    state_Y = y;
    state_Z = z;
    old_state = state;
    old_state_Y = state_Y;
    old_state_Z = state_Z;
    alpha = updateAlpha();
    old_alpha = alpha;
    logState();
    _states.push_back(state);
    _states_Y.push_back(state_Y);
    _states_Z.push_back(state_Z);
    _alphas.push_back(alpha);
    step++;
    return state;
}

double Agent::setState(double _input,double _agentCount,double stateX, long long _alpha) {
    srand((unsigned)time(NULL));
//    state = rand()%1000/(float)1000.0;
    state = stateX;
    state_Y = 0;
    input = _input;
    state_Z = gFunction(state + input/ALPHA_OF_G);
    old_state = state;
    old_state_Y = state_Y;
    old_state_Z = state_Z;
//  alpha = updateAlpha();
    alpha = _alpha;
    old_alpha = alpha;
    agentCount = _agentCount;
    _states.push_back(state);
    _states_Y.push_back(state_Y);
    _states_Z.push_back(state_Z);
    _alphas.push_back(alpha);
    step++;
    char a[8]="client";
    char fileName[50]="";
    sprintf(fileName,"%s%d_input:%.2lf.txt",a,agentId,_input);
    logfile = fopen(fileName, "w+");
    if (logfile == NULL) {
        printf("%s log open failed\n", fileName);
    }
    logState();

    return state;
}

void Agent::print_K_OF_KWTA(){
    cout<<"K_OF_KWTA: "<<K_OF_KWTA<<endl;
}

double Agent::setDiff(const double diff) {
    diff_state = diff;
}

int Agent::updateState(long long latestStateDiff,long long latestStateDiff_Y,long long latestStateDiff_Z) {
    /*
      > convert diff_state to double
      > and add to state
      > change alpha
      > log the state
    */
    old_state = state;
    old_state_Y = state_Y;
    old_state_Z = state_Z;
//    fprintf(fp, "\n%d %.3f", step, state);
    double addState = (latestStateDiff / ((double) STATE_FACTOR * ALPHA_FACTOR * ALPHA_FACTOR));
    double addState_Y = (latestStateDiff_Y / ((double) STATE_FACTOR * ALPHA_FACTOR * ALPHA_FACTOR));
    double addState_Z = (latestStateDiff_Z / ((double) STATE_FACTOR * ALPHA_FACTOR * ALPHA_FACTOR));
    double tmp  = (old_state_Y+old_state_Z)*(-1);
    double tmp2 = (K_OF_KWTA/agentCount);
//    addState+=tmp+tmp2;
    state += 0.1*(addState+tmp+tmp2);
    state_Y += 0.1*(addState_Y+addState_Z);
    double gParameter = state + input/ALPHA_OF_G;
    state_Z = gFunction(gParameter);
//    state += 0.1*addState;
//    state_Y += 0.1*addState_Y;
//    state_Z += 0.1*addState_Z;
    //明天改的代码起始点为：写gParameter中input和alphaOfGFunction的赋值点，修改K_OF_KWTA和neighborCount的赋值点
    old_alpha = alpha;
//    alpha = updateAlpha();
    _states.push_back(state);
    _states_Y.push_back(state_Y);
    _states_Z.push_back(state_Z);
    _alphas.push_back(alpha);
    step++;
//    logState();
    cout <<"step is: " << step << ",  x: " << state <<"  ,y: "<<state_Y<<"  ,z: "<<state_Z<<  endl;
    logState();
    return 0;
}

int Agent::logState() {
//    fprintf(logfile, "%8.4lf\t%2ld\t%ld\n", state, alpha, diff_state);
    fprintf(logfile, "step: %4d\tX: %8.4lf\tY: %8.4lf\tZ: %8.4lf\n", step, state, state_Y, state_Z);
}


/*
  This function is called by another Agent 
 */
int Agent::exchange(paillier_pubkey_t *pub,
                    paillier_ciphertext_t *msg_in,paillier_ciphertext_t *msg_in_Y,paillier_ciphertext_t *msg_in_Z,
                    paillier_ciphertext_t *msg_out,paillier_ciphertext_t *msg_out_Y,paillier_ciphertext_t *msg_out_Z,
                    int step) {
    paillier_plaintext_t *m_a;
//    cout << "Respond with state: " << _states[step - 1] << endl;
    long_state = (long long) llround(_states[step - 1] * STATE_FACTOR);
    long_state_Y = (long long) llround(_states_Y[step - 1] * STATE_FACTOR);
    long_state_Z = (long long) llround(_states_Z[step - 1] * STATE_FACTOR);
    m_a = paillier_plaintext_from_ui(_alphas[step - 1]);



    // encrypt the state
    paillier_plaintext_t *m_s = paillier_plaintext_from_ui(long_state);
    paillier_plaintext_t *m_s_Y = paillier_plaintext_from_ui(long_state_Y);
    paillier_plaintext_t *m_s_Z = paillier_plaintext_from_ui(long_state_Z);


    paillier_ciphertext_t *c_s = NULL;
    c_s = paillier_enc(NULL, pub, m_s,
                       paillier_get_rand_devurandom);
    paillier_ciphertext_t *c_s_Y = NULL;
    c_s_Y = paillier_enc(NULL, pub, m_s_Y,
                       paillier_get_rand_devurandom);
    paillier_ciphertext_t *c_s_Z = NULL;
    c_s_Z = paillier_enc(NULL, pub, m_s_Z,
                       paillier_get_rand_devurandom);

    paillier_ciphertext_t *c_d = paillier_create_enc_zero();
    paillier_ciphertext_t *c_d_Y = paillier_create_enc_zero();
    paillier_ciphertext_t *c_d_Z = paillier_create_enc_zero();

    // c_d = ENC( x_j + (-x_i) )
    paillier_mul(pub, c_d, msg_in, c_s);
    // c_d_Y = ENC( y_j + (-y_i) )
    paillier_mul(pub, c_d_Y, msg_in_Y, c_s_Y);
    // c_d_Z = ENC( z_j + (-z_i) )
    paillier_mul(pub, c_d_Z, msg_in_Z, c_s_Z);

    if (msg_out == NULL)
        msg_out = paillier_create_enc_zero();
    if (msg_out_Y == NULL)
        msg_out_Y = paillier_create_enc_zero();
    if (msg_out_Z == NULL)
        msg_out_Z = paillier_create_enc_zero();

    // msg_out = ENC( alpha * (x_j + (-x_i) )
    paillier_exp(pub, msg_out, c_d, m_a);
    // msg_out = ENC( alpha * (y_j + (-y_i) )
    paillier_exp(pub, msg_out_Y, c_d_Y, m_a);
    // msg_out = ENC( alpha * (z_j + (-z_i) )
    paillier_exp(pub, msg_out_Z, c_d_Z, m_a);


    paillier_freeplaintext(m_s);
    paillier_freeplaintext(m_a);
    paillier_freeciphertext(c_s);
    paillier_freeciphertext(c_d);

    paillier_freeplaintext(m_s_Y);
    paillier_freeciphertext(c_s_Y);
    paillier_freeciphertext(c_d_Y);

    paillier_freeplaintext(m_s_Z);
    paillier_freeciphertext(c_s_Z);
    paillier_freeciphertext(c_d_Z);
    return 0;
}

long long Agent::ciphertext_to_long(paillier_ciphertext_t *c) {
    paillier_plaintext_t *m = paillier_dec(NULL, pubKey, prvKey, c);

    size_t nBytes = 0;
    unsigned char *bytes = (unsigned char *) mpz_export(0, &nBytes, 1, 1, 0, 0, m->m);

    long long e = 0;
    //如果是在32位系统下运行，此处变量e的类型要给为int，否则转换负数时会出错
//    int e = 0;

//    int i = nBytes - sizeof(long long);
//    for (; i < nBytes; i++) {
//        e = (e << 8) | bytes[i];
//    }

    for (int i = 0; i < nBytes; i++) {
        e = (e << 8) | bytes[i];
    }

    paillier_freeplaintext(m);
    free(bytes);
    return e;
}

long long Agent::updateAlpha() {
    return rand() % ALPHA_FACTOR + 1;
    //  return ALPHA_FACTOR;
    //return alpha;
}

double Agent::gFunction(double x) {
    if (x<0){
        return 0;
    }
    if (x>1){
        return 1;
    }
    return x;
}


