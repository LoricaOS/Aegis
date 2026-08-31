#include "cryptroot.h"
#include "cryptroot_crypto.h"
#include "blkdev.h"
#include "kbd.h"
#include "arch.h"
#include "printk.h"
#include <stdint.h>

#define HEADER_SECTORS 8u
#define PBKDF2_MIN 10000u
#define PBKDF2_MAX 2000000u
static const uint8_t magic[8]={'L','O','R','I','C','R','Y','1'};

typedef struct { blkdev_t *parent; cryptroot_xts_ctx_t xts; } crypt_priv_t;
static crypt_priv_t priv;
static blkdev_t cryptdev;

static uint32_t le32(const uint8_t *p)
{ return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }

static int ct_equal(const uint8_t *a,const uint8_t *b,uint32_t n)
{ uint8_t d=0;for(uint32_t i=0;i<n;i++)d|=a[i]^b[i];return d==0; }

static uint32_t password_read(uint8_t out[128])
{
    uint32_t n=0; char c;
    for (;;) {
        while (!kbd_poll(&c)) arch_wait_for_irq();
        if (c=='\r'||c=='\n') { printk("\n"); return n; }
        if ((c=='\b'||c==127) && n) { n--; continue; }
        if (c>=32 && c<127 && n<127) out[n++]=(uint8_t)c;
    }
}

static int crypt_read(blkdev_t *d,uint64_t lba,uint32_t count,void *buf)
{
    crypt_priv_t *p=d->priv;
    if (lba>d->block_count || count>d->block_count-lba ||
        p->parent->read(p->parent,lba+HEADER_SECTORS,count,buf)<0) return -1;
    uint8_t *b=buf;for(uint32_t i=0;i<count;i++)cryptroot_xts(&p->xts,b+512u*i,512,lba+i,0);
    return 0;
}

static int crypt_write(blkdev_t *d,uint64_t lba,uint32_t count,const void *buf)
{
    crypt_priv_t *p=d->priv;uint8_t tmp[512];const uint8_t *b=buf;
    if (lba>d->block_count || count>d->block_count-lba) return -1;
    for(uint32_t i=0;i<count;i++){
        __builtin_memcpy(tmp,b+512u*i,512);cryptroot_xts(&p->xts,tmp,512,lba+i,1);
        if(p->parent->write(p->parent,lba+HEADER_SECTORS+i,1,tmp)<0){__builtin_memset(tmp,0,512);return -1;}
    }
    __builtin_memset(tmp,0,512);return 0;
}

const char *cryptroot_open(const char *devname)
{
    static uint8_t header[4096];uint8_t pw[128],key[64],check[32];
    blkdev_t *parent=blkdev_get(devname);if(!parent||parent->block_size!=512||parent->block_count<=HEADER_SECTORS)return devname;
    if(parent->read(parent,0,HEADER_SECTORS,header)<0)return devname;
    if(__builtin_memcmp(header,magic,8)!=0)return devname;
    uint32_t version=le32(header+8),hs=le32(header+12),rounds=le32(header+16);
    if(version!=1||hs!=HEADER_SECTORS||rounds<PBKDF2_MIN||rounds>PBKDF2_MAX){printk("[CRYPT] FAIL: invalid encrypted-root header on %s\n",devname);return 0;}
    int quiet=printk_get_quiet();printk_set_quiet(0);
    for(int tries=0;tries<3;tries++){
        printk("Unlock LoricaOS root: ");uint32_t n=password_read(pw);
        cryptroot_pbkdf2(pw,n,header+20,rounds,key);cryptroot_verifier(key,check);__builtin_memset(pw,0,sizeof(pw));
        if(ct_equal(check,header+36,32)){
            priv.parent=parent;cryptroot_xts_init(&priv.xts,key);__builtin_memset(key,0,sizeof(key));__builtin_memset(check,0,sizeof(check));
            __builtin_memset(&cryptdev,0,sizeof(cryptdev));__builtin_memcpy(cryptdev.name,"cryptroot",10);
            cryptdev.block_count=parent->block_count-HEADER_SECTORS;cryptdev.block_size=512;cryptdev.read=crypt_read;cryptdev.write=crypt_write;cryptdev.priv=&priv;
            if(blkdev_register(&cryptdev)<0){printk("[CRYPT] FAIL: block device table full\n");printk_set_quiet(quiet);return 0;}
            printk("[CRYPT] OK: encrypted root unlocked\n");printk_set_quiet(quiet);return cryptdev.name;
        }
        __builtin_memset(key,0,sizeof(key));__builtin_memset(check,0,sizeof(check));printk("Incorrect passphrase\n");
    }
    printk("[CRYPT] FAIL: unlock attempts exhausted\n");printk_set_quiet(quiet);return 0;
}
