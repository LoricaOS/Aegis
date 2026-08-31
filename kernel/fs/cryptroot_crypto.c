#include "cryptroot_crypto.h"

typedef struct { uint32_t h[8]; uint64_t bits; uint8_t buf[64]; uint32_t used; } sha256_t;
static const uint32_t k256[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static uint32_t rr(uint32_t x,uint32_t n){return(x>>n)|(x<<(32-n));}
static void block(sha256_t*c,const uint8_t*p){uint32_t w[64],a,b,d,e,f,g,h,i,t,u,cc;for(i=0;i<16;i++)w[i]=(uint32_t)p[4*i]<<24|(uint32_t)p[4*i+1]<<16|(uint32_t)p[4*i+2]<<8|p[4*i+3];for(;i<64;i++){a=w[i-15];b=w[i-2];w[i]=(rr(b,17)^rr(b,19)^(b>>10))+w[i-7]+(rr(a,7)^rr(a,18)^(a>>3))+w[i-16];}a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];for(i=0;i<64;i++){t=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+k256[i]+w[i];u=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&cc)^(b&cc));h=g;g=f;f=e;e=d+t;d=cc;cc=b;b=a;a=t+u;}c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;}
static void si(sha256_t*c){static const uint32_t v[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};for(int i=0;i<8;i++)c->h[i]=v[i];c->bits=0;c->used=0;}
static void su(sha256_t*c,const uint8_t*p,uint32_t n){while(n){uint32_t z=64-c->used;if(z>n)z=n;__builtin_memcpy(c->buf+c->used,p,z);c->used+=z;p+=z;n-=z;c->bits+=(uint64_t)z*8;if(c->used==64){block(c,c->buf);c->used=0;}}}
static void so(sha256_t*c,uint8_t out[32]){uint64_t n=c->bits;c->buf[c->used++]=0x80;if(c->used>56){while(c->used<64)c->buf[c->used++]=0;block(c,c->buf);c->used=0;}while(c->used<56)c->buf[c->used++]=0;for(int i=7;i>=0;i--)c->buf[c->used++]=(uint8_t)(n>>(8*i));block(c,c->buf);for(int i=0;i<8;i++){out[4*i]=c->h[i]>>24;out[4*i+1]=c->h[i]>>16;out[4*i+2]=c->h[i]>>8;out[4*i+3]=c->h[i];}}
static void hm(const uint8_t*k,uint32_t kn,const uint8_t*m,uint32_t mn,uint8_t o[32]){uint8_t x[64]={0},p[64],in[32];sha256_t c;if(kn>64){si(&c);su(&c,k,kn);so(&c,x);kn=32;}else __builtin_memcpy(x,k,kn);for(int i=0;i<64;i++)p[i]=x[i]^0x36;si(&c);su(&c,p,64);su(&c,m,mn);so(&c,in);for(int i=0;i<64;i++)p[i]=x[i]^0x5c;si(&c);su(&c,p,64);su(&c,in,32);so(&c,o);__builtin_memset(x,0,64);__builtin_memset(p,0,64);__builtin_memset(in,0,32);}
void cryptroot_pbkdf2(const uint8_t*pw,uint32_t pn,const uint8_t salt[16],uint32_t rounds,uint8_t key[64]){uint8_t m[20],u[32],t[32];__builtin_memcpy(m,salt,16);if(!rounds)rounds=1;for(uint32_t b=1;b<=2;b++){m[16]=b>>24;m[17]=b>>16;m[18]=b>>8;m[19]=b;hm(pw,pn,m,20,u);__builtin_memcpy(t,u,32);for(uint32_t r=1;r<rounds;r++){hm(pw,pn,u,32,u);for(int i=0;i<32;i++)t[i]^=u[i];}__builtin_memcpy(key+32*(b-1),t,32);}__builtin_memset(u,0,32);__builtin_memset(t,0,32);}
void cryptroot_verifier(const uint8_t k[64],uint8_t o[32]){static const uint8_t m[]="LoricaOS encrypted root";hm(k,64,m,sizeof(m)-1,o);}

static uint8_t sb[256],ib[256],m2[256],m3[256],m9[256],m11[256],m13[256],m14[256];static int tables;
static uint8_t gm(uint8_t a,uint8_t b){uint8_t r=0;while(b){if(b&1)r^=a;a=(uint8_t)((a<<1)^((a&0x80)?0x1b:0));b>>=1;}return r;}
static uint8_t rot8(uint8_t x,int n){return(uint8_t)((x<<n)|(x>>(8-n)));}
static void init_tables(void){if(tables)return;for(int x=0;x<256;x++){uint8_t a=x,y=1,e=254;while(e){if(e&1)y=gm(y,a);a=gm(a,a);e>>=1;}if(!x)y=0;sb[x]=(uint8_t)(y^rot8(y,1)^rot8(y,2)^rot8(y,3)^rot8(y,4)^0x63);ib[sb[x]]=(uint8_t)x;m2[x]=gm(x,2);m3[x]=gm(x,3);m9[x]=gm(x,9);m11[x]=gm(x,11);m13[x]=gm(x,13);m14[x]=gm(x,14);}tables=1;}
static void expand(const uint8_t k[32],uint8_t r[240]){uint8_t rc=1,t[4];uint32_t n=32;__builtin_memcpy(r,k,32);while(n<240){for(int i=0;i<4;i++)t[i]=r[n-4+i];if(n%32==0){uint8_t q=t[0];t[0]=sb[t[1]]^rc;t[1]=sb[t[2]];t[2]=sb[t[3]];t[3]=sb[q];rc=gm(rc,2);}else if(n%32==16)for(int i=0;i<4;i++)t[i]=sb[t[i]];for(int i=0;i<4;i++){r[n]=r[n-32]^t[i];n++;}}}
static void ak(uint8_t*s,const uint8_t*k){for(int i=0;i<16;i++)s[i]^=k[i];}
static void sh(uint8_t*s,int inv){uint8_t t[16];for(int r=0;r<4;r++)for(int c=0;c<4;c++)t[r+4*c]=s[r+4*((c+(inv?4-r:r))&3)];__builtin_memcpy(s,t,16);}
static void mx(uint8_t*s,int inv){for(int c=0;c<4;c++){uint8_t*p=s+4*c,a=p[0],b=p[1],d=p[2],e=p[3];if(!inv){p[0]=m2[a]^m3[b]^d^e;p[1]=a^m2[b]^m3[d]^e;p[2]=a^b^m2[d]^m3[e];p[3]=m3[a]^b^d^m2[e];}else{p[0]=m14[a]^m11[b]^m13[d]^m9[e];p[1]=m9[a]^m14[b]^m11[d]^m13[e];p[2]=m13[a]^m9[b]^m14[d]^m11[e];p[3]=m11[a]^m13[b]^m9[d]^m14[e];}}}
static void aes(uint8_t*s,const uint8_t*r,int enc){if(enc){ak(s,r);for(int n=1;n<14;n++){for(int i=0;i<16;i++)s[i]=sb[s[i]];sh(s,0);mx(s,0);ak(s,r+16*n);}for(int i=0;i<16;i++)s[i]=sb[s[i]];sh(s,0);ak(s,r+224);}else{ak(s,r+224);for(int n=13;n>0;n--){sh(s,1);for(int i=0;i<16;i++)s[i]=ib[s[i]];ak(s,r+16*n);mx(s,1);}sh(s,1);for(int i=0;i<16;i++)s[i]=ib[s[i]];ak(s,r);}}
void cryptroot_xts_init(cryptroot_xts_ctx_t*c,const uint8_t k[64]){init_tables();expand(k,c->data_rk);expand(k+32,c->tweak_rk);}
static void mulx(uint8_t*t){uint8_t carry=0;for(int i=0;i<16;i++){uint8_t n=t[i]>>7;t[i]=(uint8_t)((t[i]<<1)|carry);carry=n;}if(carry)t[0]^=0x87;}
void cryptroot_xts(cryptroot_xts_ctx_t*c,uint8_t*d,uint32_t n,uint64_t sector,int enc){uint8_t t[16]={0};for(int i=0;i<8;i++)t[i]=(uint8_t)(sector>>(8*i));aes(t,c->tweak_rk,1);for(uint32_t o=0;o+16<=n;o+=16){for(int i=0;i<16;i++)d[o+i]^=t[i];aes(d+o,c->data_rk,enc);for(int i=0;i<16;i++)d[o+i]^=t[i];mulx(t);}__builtin_memset(t,0,16);}
