/*
 * Data Encryption Standard
 * An approach to DES algorithm
 *
 * By: Rajat Kumar
 * Version: 0.1
 *
 * source : http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstdio>

using namespace std;

#include "Lib.h"
#define Encrypt true
#define Decrypt false

class DES{
    string plaintext;
    string ciphertext;
    string key;
    vector <int> key_perm_1;
    vector <int> key_gen[16];
    const int *perm_1;
    const int *perm_2;
    const int *IP_perm;
    const int *IP_inverse_perm;
    const int *E_perm;
    const int *P_perm;
    static int S[8][4][16];
    
    public :
    DES(string pt,string k,int hexp,int hexk)
    {
        if(hexp)
            plaintext = Lib::hex_to_string(pt);
        else plaintext = pt;
        if(hexk)
            key = Lib::hex_to_string(k);
        else key = k;
        
        _init();
        
        perm_cycle_1();
        create_keys();
        perm_cycle_2();
    }
    
    void _init()
    {
        //Initialization of all blocks
        
        //PC-1 block
        static int a[] = {57,49,41,33,25,17,9,1,
        58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
        60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,
        30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
        
        //PC-2 block
        static int b[] = {14,17,11,24,1,5,3,28,15,6,
            21,10,23,19,12,4,26,8,16,7,27,20,13,
            2,41,52,31,37,47,55,30,40,51,45,33,
            48,44,49,39,56,34,53,46,42,50,36,29,32};
        
        //IP block
        static int c[] = {58,50,42,34,26,18,10,2,60,52,44,
            36,28,20,12,4,62,54,46,38,30,22,14,6,64,
            56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,61,53,45,37,29,21,
            13,5,63,55,47,39,31,23,15,7};
        
        //IP inverse block
        static int d[] = {40,8,48,16,56,24,64,32,39,7,47,
            15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,
            53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,
            19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
        
        //E block
        static int e[] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,
            13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,
            22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
        
        //P Block
        static int f[] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
        
        
        
        perm_1 = a;
        perm_2 = b;
        IP_perm = c;
        IP_inverse_perm = d;
        E_perm = e;
        P_perm = f;
    }
    
    void encrypt()
    {
        //Encryption of the plaintext
        string s;
        vector <int> v;
        
        ciphertext.clear();
        
        //8 bytes of message is encoded in each step
        for(int i=0;i<plaintext.length();i+=8){
            if(i+8<=plaintext.length())
                s = string(plaintext.begin()+i,plaintext.begin()+i+8);
            else
                s = string(plaintext.begin()+i,plaintext.end());
            
            v = Lib::string_to_binary(s);
            
            //pad zeros
            Lib::pad_zeros(v);
            
            s = Lib::binary_to_hex(encode_message(v,Encrypt));
            ciphertext.insert(ciphertext.end(),s.begin(),s.end());
        }
    }
    
    void decrypt()
    {
        //Decryption of plaintext
        string s;
        vector <int> v;
        
        ciphertext.clear();
        
        //8 bytes of message is encoded in each step
        for(int i=0;i<plaintext.length();i+=8){
            if(i+8<=plaintext.length())
            s = string(plaintext.begin()+i,plaintext.begin()+i+8);
            else
            s = string(plaintext.begin()+i,plaintext.end());
            
            v = Lib::string_to_binary(s);
            
            //pad zeros
            Lib::pad_zeros(v);
            
            s = Lib::binary_to_hex(encode_message(v,Decrypt));
            ciphertext.insert(ciphertext.end(),s.begin(),s.end());
        }
    }
    
    void perm_cycle_1()
    {
        //Permutation of original key
        vector <int> key_old = Lib::string_to_binary(key);
        
        vector <int> key_new(56);
        Lib::pad_zeros(key_old);
        
        for(int i=0;i<56;i++)
            key_new[i] = key_old[perm_1[i]-1];
        
        key_perm_1 = vector<int>(key_new);
    }
    
    void create_keys()
    {
        //Creation of the 16 keys by shifting the initial keys
        vector <int> c,d;
        
        c = vector<int>(key_perm_1.begin(),key_perm_1.begin()+28);
        d = vector<int>(key_perm_1.begin()+28,key_perm_1.end());
        
        //Apply shift and generate each 16 keys
        for(int i=0;i<16;i++){
            int shift = 2;
            if(i<2||i==8||i==15) shift--;
            rotate(c.begin(),c.begin()+shift,c.end());
            rotate(d.begin(),d.begin()+shift,d.end());
            
            key_gen[i].insert(key_gen[i].end(),c.begin(),c.end());
            key_gen[i].insert(key_gen[i].end(),d.begin(),d.end());
        }
        
    }
    
    void perm_cycle_2()
    {
        //Permutaion of the 16 keys generated using shift
        vector <int> key_new(48);
        
        for(int i=0;i<16;i++){
            for(int j=0;j<48;j++)
                key_new[j] = key_gen[i][perm_2[j]-1];
            key_gen[i] = vector<int>(key_new);
        }
    }
    
    vector<int> encode_message(vector <int> v,bool mode)
    {
        //Encode each 64 bits of message
        vector <int> IP(64);
        vector <int> IP_inverse(64);
        
        //Permute the message using IP block
        for(int i=0;i<64;i++)
            IP[i] = v[IP_perm[i]-1];
        
        vector <int> L0,R0,L,R;
        
        //Break the message IP in two parts
        L0 = vector <int> (IP.begin(),IP.begin()+32);
        R0 = vector <int> (IP.begin()+32,IP.end());
        
        for(int i=0;i<16;i++){
            L = vector <int> (R0);
            if(mode == Encrypt)
            R = f_function(R0,i);
            else R=f_function(R0,16-i-1);
            
            for(int i=0;i<32;i++)
            R[i] = R[i]^L0[i];
            
            L0 = vector <int>(L);
            R0 = vector <int>(R);
        }
        
        //IP = R0.L0
        IP.clear();
        IP.insert(IP.end(),R0.begin(),R0.end());
        IP.insert(IP.end(),L0.begin(),L0.end());
        
        //Generate IP inverse using IPinverse permutation block
        for(int i=0;i<64;i++)
        IP_inverse[i] = IP[IP_inverse_perm[i]-1];
        
        return IP_inverse;
    }
    
    vector <int> f_function(vector <int> R,int key_index)
    {
        //function to calculate the R for each iteration
        vector <int> E(48);
        vector <int> F;
        
        //Generate E(R) using bit selection table
        //R = K^E(R)
        for(int i=0;i<48;i++)
            E[i] = key_gen[key_index][i]^R[E_perm[i]-1];
        
        //Convert each 6 blocks of bit into 4 blocks using Sbox
        for(int i=0;i<48;i+=6){
            int x = (E[i]<<1)+E[i+5];
            int y = 0;
            for(int j=0;j<4;j++)
            y = (y<<1)+E[i+j+1];
            
            vector <int> v = Lib::number_to_binary(S[(i+1)/6][x][y]);
            F.insert(F.end(),v.begin(),v.end());
        }
        
        vector <int> P(32);
        
        //Permute the generate R using P block
        for(int i=0;i<32;i++)
        P[i] = F[P_perm[i]-1];
        
        return P;
    }
    
    string get_ciphertext()
    {
        return ciphertext;
    }
};

int DES::S[8][4][16] = {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
},
    
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }};

int main()
{
    string s;
    string t;
    char hexp,hexk;
    int choice,fchoice;
    
    cout<<"Enter your message :: "<<endl;
    getline(cin,s);
    
    cout<<"Is plain/ciphertext in hex?[y/n]"<<endl;
    do{
        cin>>hexp;
        if(hexp!='y'&&hexp!='Y'&&hexp!='n'&&hexp!='N')
        cout<<"Enter [y/n]: ";
        else break;
    }while(true);
    if(hexp=='y'||hexp=='Y')    hexp=1;
    else hexp = 0;
    
    cout<<"Enter your key :: "<<endl;
    getchar();
    getline(cin,t);
    cout<<"Is Key in hex?[y/n]"<<endl;
    do{
        cin>>hexk;
        if(hexk!='y'&&hexk!='Y'&&hexk!='n'&&hexk!='N')
        cout<<"Enter [y/n]: ";
        else break;
    }while(true);
    if(hexk=='y'||hexk=='Y')    hexk=1;
    else hexk = 0;
    
    DES des(s,t,hexp,hexk);
    
    cout<<"Enter your Choice::"<<endl;
    cout<<"1. Encrypt the message"<<endl;
    cout<<"2. Decrypt the message"<<endl;
    cin>>choice;
    cout<<"Enter your Choice::"<<endl;
    cout<<"1. Get the output in plaintext"<<endl;
    cout<<"2. Get the output in hex"<<endl;
    cin>>fchoice;
    switch(choice){
        case 2:
        des.decrypt();
        if(fchoice==2)
        cout<<"plaintext is : "<<des.get_ciphertext()<<endl;
        else
        cout<<"plaintext is : "<<Lib::hex_to_string(des.get_ciphertext())<<endl;
        break;
        default:
        des.encrypt();
        if(fchoice==2)
        cout<<"ciphertext is : "<<des.get_ciphertext()<<endl;
        else
        cout<<"ciphertext is : "<<Lib::hex_to_string(des.get_ciphertext())<<endl;
    }
}
