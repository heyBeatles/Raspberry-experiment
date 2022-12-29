/*
	Agent class
*/

#ifndef AGENT_H
#define AGENT_H

#include <cstdio>
#include <cstdlib>
#include <string>
#include <list>
#include <vector>
#include <gmp.h>
//#include <paillier.h>

extern "C"
{
#include "paillier.h"
}



//typedef unsigned long long ulong;
struct myVector {
    int port;
    int step = 0;
    double diff = 0.0;
    char ipaddr[];
};

class Agent {
public:
    Agent();

    ~Agent();

    double setState(double _input,double _agentCount,double stateX, long long alpha);
    double setState(double x,double y,double z);
    void print_K_OF_KWTA();

    double getState() { return state; }

    double getAlpha() { return alpha; }

    double setDiff(const double diff);

    /*
      Send inquiries to all neighbors and do computation
      without updating its states
     */
    int communicate();

    myVector _myVector[10];

    /*
      Update the internal states
    */
    int updateState(long long latestStateDiff,long long latestStateDiff_Y,long long latestStateDiff_Z);

    int logState();

    double old_alpha = 0.0;
    double old_state = 0.0;
    double old_state_Y = 0.0;
    double old_state_Z = 0.0;


    /*
      Process another agent's inquiry
     */
    int exchange(paillier_pubkey_t *pub,
                 paillier_ciphertext_t *msg_in,paillier_ciphertext_t *msg_in_Y,paillier_ciphertext_t *msg_in_Z,
                 paillier_ciphertext_t *msg_out,paillier_ciphertext_t *msg_out_Y,paillier_ciphertext_t *msg_out_Z,
                 int step);

    long long ciphertext_to_long(paillier_ciphertext_t *c);

    // Generate a new random weight alpha
    long long updateAlpha();

    // function to update state variable z
   double gFunction(double x);

   void setAgentId(int id);

    std::string id;
    // For illustrative purpose, state is a scalar
    double state;
    double state_Y;
    double state_Z;
    double input;
    int agentId;
    long long alpha;
    long long long_state;
    long long long_state_Y;
    long long long_state_Z;
    long long diff_state;
    long long diff_state_Y;
    long long diff_state_Z;
    double agentCount;
    std::vector<double> _states;
    std::vector<double> _states_Y;
    std::vector<double> _states_Z;
    std::vector<double> _alphas;
    int step = 0;
    int port;
    FILE *logfile = NULL;
    FILE *fp = NULL;
    paillier_pubkey_t *pubKey = NULL;
    paillier_prvkey_t *prvKey = NULL;
    char ipaddr[];
};


#endif
