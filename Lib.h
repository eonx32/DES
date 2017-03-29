/*
 * Some important functions
 * for implementing DES
 */

class Lib
{
    public :
    static vector<int> string_to_binary(string s)
    {
        vector<int> t;
        
        for(int i=0;i<s.length();i++){
            
            char j = s[i];
            
            for(int k=7;k>=0;k--)
            t.push_back((j&(1<<k))!=0);
        }
        
        return t;
    }
    
    static string binary_to_string(vector<int> s)
    {
        string t;
        
        for(int i=0;i<s.size();){
            
            char j = 0;
            
            for(int k=7;k>=0;i++,k--)
            if(s[i])
            j+=(1<<k);
            t.push_back(j);
        }
        
        return t;
    }
    
    static string binary_to_hex(vector<int> s)
    {
        char h[16] = {'0','1','2','3','4','5','6',
            '7','8','9','A','B','C','D','E','F'};
        
        string t;
        
        for(int i=0;i<s.size();){
            
            char j = 0;
            
            for(int k=3;k>=0;i++,k--)
            if(s[i])
            j+=(1<<k);
            t.push_back(h[j]);
        }
        
        return t;
    }
    
    static vector<int> hex_to_binary(string s)
    {
        char h[16] = {'0','1','2','3','4','5','6',
            '7','8','9','A','B','C','D','E','F'};
        char x[128];
        
        for(int i=0;i<16;i++)
        x[h[i]] = i;
        
        vector<int> t;
        
        for(int i=0;i<s.length();i++){
            
            char j = x[s[i]];
            
            for(int k=3;k>=0;k--)
            t.push_back((j&(1<<k))!=0);
            
        }
        
        return t;
    }
    
    static string hex_to_string(string s)
    {
        return binary_to_string(hex_to_binary(s));
    }
    
    static string string_to_hex(string s)
    {
        return binary_to_hex(string_to_binary(s));
    }
    
    static vector <int> long_to_binary(long long n,int length)
    {
        vector <int> v;
        for(int k=length-1;k>=0;k--)
        v.push_back((n&(1LL<<k))!=0);
        
        return v;
    }
    
    static void pad_zeros(vector<int> &v)
    {
        int n = v.size();
        int m = 0;
        int length = 0;
        if(n%64){
            m = ((n+63)/64-1)*64 + n%64;
            length = ((n+63)/64)*64;
        }
        
        for(int i=m;i<length;i++)
        v.push_back(0);
    }
    
    static void print_vector(vector<int> v)
    {
        for(int i=0;i<v.size();i++)
        cout<<v[i];
        cout<<endl;
    }
};
