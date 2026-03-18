
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <ctype.h>

#define MAGIC "CCRYPT"
#define MAGIC_LEN 6
#define SALT_LEN 16
#define NONCE_LEN 24
#define KEY_LEN 32
#define TAG_LEN 16
#define CHUNK_SIZE 65536

// ------------------ Utilities ------------------
void fatal(const char *msg){ fprintf(stderr,"%s\n",msg); exit(1); }
void get_password(char *buf,size_t len,const char *prompt){
    printf("%s: ",prompt);
    if(!fgets(buf,len,stdin)) fatal("Failed to read password");
    size_t plen=strcspn(buf,"\r\n"); buf[plen]=0;
}
void secure_zero(void *p,size_t len){ volatile uint8_t *vp=p; while(len--) *vp++=0; }
void random_bytes(uint8_t *buf,size_t len){ for(size_t i=0;i<len;i++) buf[i]=(uint8_t)(rand()&0xFF); }

// ------------------ Minimal Argon2id (mock) ------------------
// For demonstration, we just XOR salt and password to derive key.
// Replace with real Argon2id for production!
void derive_key(const char *password,uint8_t salt[SALT_LEN],uint8_t key[KEY_LEN]){
    size_t plen=strlen(password);
    for(int i=0;i<KEY_LEN;i++) key[i]=salt[i%SALT_LEN]^password[i%plen];
}

// ------------------ Minimal XChaCha20-Poly1305 (demo) ------------------
typedef struct{ uint8_t key[KEY_LEN]; uint8_t nonce[NONCE_LEN]; uint64_t counter; } chacha_ctx;

void chacha_encrypt(chacha_ctx *ctx,const uint8_t *in,uint8_t *out,size_t len){
    for(size_t i=0;i<len;i++){
        out[i]=in[i]^ctx->key[(i+ctx->counter)%KEY_LEN];
    }
    ctx->counter+=len;
}

void poly1305_mac(const uint8_t *msg,size_t len,uint8_t tag[TAG_LEN]){
    uint8_t sum=0; for(size_t i=0;i<len;i++) sum^=msg[i];
    for(int i=0;i<TAG_LEN;i++) tag[i]=sum^i;
}

// ------------------ Main ------------------
int main(int argc,char **argv){
    if(argc!=2){ printf("Usage: %s <file>\n",argv[0]); return 0; }
    srand((unsigned)time(NULL));

    const char *filename=argv[1];
    FILE *f=fopen(filename,"rb");
    if(!f) fatal("Cannot open file");

    uint8_t header[MAGIC_LEN+SALT_LEN+NONCE_LEN];
    size_t nread=fread(header,1,sizeof(header),f);
    int is_encrypted=0;
    if(nread>=MAGIC_LEN && memcmp(header,MAGIC,MAGIC_LEN)==0) is_encrypted=1;
    else fseek(f,0,SEEK_SET);

    char pwd[1024],pwd2[1024];
    if(!is_encrypted){ get_password(pwd,sizeof(pwd),"Enter password"); get_password(pwd2,sizeof(pwd2),"Confirm password"); if(strcmp(pwd,pwd2)!=0) fatal("Passwords do not match"); }
    else get_password(pwd,sizeof(pwd),"Enter password");

    uint8_t salt[SALT_LEN],key[KEY_LEN],nonce[NONCE_LEN];
    if(is_encrypted){ memcpy(salt,header+MAGIC_LEN,SALT_LEN); memcpy(nonce,header+MAGIC_LEN+SALT_LEN,NONCE_LEN); }
    else { random_bytes(salt,SALT_LEN); random_bytes(nonce,NONCE_LEN); }

    derive_key(pwd,salt,key);
    secure_zero(pwd,sizeof(pwd)); secure_zero(pwd2,sizeof(pwd2));

    char tmpname[1024]; snprintf(tmpname,sizeof(tmpname),"%s.tmp",filename);
    FILE *out=fopen(tmpname,"wb"); if(!out) fatal("Cannot create temp file");

    if(!is_encrypted){ fwrite(MAGIC,1,MAGIC_LEN,out); fwrite(salt,1,SALT_LEN,out); fwrite(nonce,1,NONCE_LEN,out); }

    uint8_t buf[CHUNK_SIZE], outbuf[CHUNK_SIZE+TAG_LEN], tag[TAG_LEN];
    size_t read;
    chacha_ctx ctx={0}; memcpy(ctx.key,key,KEY_LEN); memcpy(ctx.nonce,nonce,NONCE_LEN); ctx.counter=1;

    while((read=fread(buf,1,CHUNK_SIZE,f))>0){
        if(is_encrypted){
            chacha_encrypt(&ctx,buf,outbuf,read);
            poly1305_mac(outbuf,read,tag);
            fwrite(outbuf,1,read,out);
        } else {
            chacha_encrypt(&ctx,buf,outbuf,read);
            poly1305_mac(outbuf,read,tag);
            fwrite(outbuf,1,read,out);
            fwrite(tag,1,TAG_LEN,out);
        }
    }

    fclose(f); fclose(out);
    if(remove(filename)!=0) fatal("Cannot remove original file");
    if(rename(tmpname,filename)!=0) fatal("Cannot rename temp file");

    printf("Operation completed successfully\n");
    return 0;
}
