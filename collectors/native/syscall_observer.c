/* Read-only Linux x86_64 child/descendant ptrace observation, NOT eBPF.
 * No POKE or SETREGS operations. Explicit launch; never attach other workloads.
 */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <fcntl.h>

struct trace_info {
    unsigned char op, pad[3]; unsigned int arch;
    unsigned long long ip, sp;
    union { struct { unsigned long long nr,args[6]; } entry;
            struct { long long value; unsigned char error; } exit; } data;
};
struct thread { pid_t pid; long nr; uint64_t args[6],start; char path[1024],other[1024]; int truncated; } threads[4096];
static FILE *out; static unsigned long sequence; static int failures;
static uint64_t now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }
static void quote(const char *s) {
    fputc('"',out);
    for (;*s;s++) { unsigned char c=*s;
        if(c=='"'||c=='\\')fprintf(out,"\\%c",c);
        else if(c<32||c>=127)fprintf(out,"\\u%04x",c); else fputc(c,out);
    }
    fputc('"',out);
}
static struct thread *get(pid_t pid) {
    for(int i=0;i<4096;i++)if(threads[i].pid==pid)return &threads[i];
    for(int i=0;i<4096;i++)if(!threads[i].pid){threads[i].pid=pid;threads[i].nr=-1;return &threads[i];}
    return NULL;
}
static int text_at(pid_t pid,unsigned long address,char *buf,size_t size) {
    size_t n=0; if(!address){buf[0]=0;return 0;}
    while(n+sizeof(long)<size) {
        errno=0; long v=ptrace(PTRACE_PEEKDATA,pid,(void*)(address+n),0);
        if(errno){buf[n]=0;return 1;}
        for(size_t i=0;i<sizeof(long);i++){buf[n++]=((char*)&v)[i];if(!buf[n-1])return 0;}
    }
    buf[n]=0; return 1;
}
static void fd_path(pid_t pid,long fd,char *buf,size_t size) {
    char name[80];snprintf(name,sizeof(name),"/proc/%d/fd/%ld",pid,fd);
    ssize_t n=readlink(name,buf,size-1);if(n<0)buf[0]=0;else buf[n]=0;
}
static const char *sysname(long n) {
    switch(n) {
    case SYS_execve:return "execve";case SYS_execveat:return "execveat";
    case SYS_open:return "open";case SYS_openat:return "openat";case SYS_unlink:return "unlink";
    case SYS_unlinkat:return "unlinkat";case SYS_rename:return "rename";case SYS_renameat:return "renameat";
    case SYS_renameat2:return "renameat2";case SYS_mkdir:return "mkdir";case SYS_mkdirat:return "mkdirat";
    case SYS_rmdir:return "rmdir";case SYS_write:return "write";case SYS_pwrite64:return "pwrite64";
    case SYS_read:return "read";case SYS_pread64:return "pread64";case SYS_ftruncate:return "ftruncate";
    case SYS_connect:return "connect";case SYS_sendto:return "sendto";case SYS_sendmsg:return "sendmsg";
    case SYS_fsync:return "fsync";case SYS_fdatasync:return "fdatasync";default:return NULL;
    }
}
static void begin(struct thread *t,struct trace_info *info) {
    t->nr=info->data.entry.nr;memcpy(t->args,info->data.entry.args,sizeof(t->args));t->start=now_ns();
    t->path[0]=t->other[0]=0;t->truncated=0;
    switch(t->nr) {
    case SYS_open:case SYS_execve:case SYS_unlink:case SYS_rmdir:case SYS_mkdir:case SYS_rename:
        t->truncated|=text_at(t->pid,t->args[0],t->path,sizeof(t->path));break;
    case SYS_openat:case SYS_execveat:case SYS_unlinkat:case SYS_mkdirat:case SYS_renameat:case SYS_renameat2:
        t->truncated|=text_at(t->pid,t->args[1],t->path,sizeof(t->path));break;
    case SYS_write:case SYS_pwrite64:case SYS_read:case SYS_pread64:case SYS_ftruncate:case SYS_fsync:case SYS_fdatasync:
        fd_path(t->pid,t->args[0],t->path,sizeof(t->path));break;
    }
    if(t->nr==SYS_rename)t->truncated|=text_at(t->pid,t->args[1],t->other,sizeof(t->other));
    if(t->nr==SYS_renameat||t->nr==SYS_renameat2)t->truncated|=text_at(t->pid,t->args[3],t->other,sizeof(t->other));
}
static void end(struct thread *t,long long result) {
    const char *name=sysname(t->nr);if(!name)return;
    fprintf(out,"{\"sequence\":%lu,\"kind\":\"syscall\",\"pid\":%d,\"syscall\":",sequence++,t->pid);quote(name);
    fprintf(out,",\"start_ns\":%llu,\"end_ns\":%llu,\"result\":%lld,\"path\":",
        (unsigned long long)t->start,(unsigned long long)now_ns(),result);quote(t->path);
    fputs(",\"other_path\":",out);quote(t->other);
    fprintf(out,",\"path_truncated_or_unreadable\":%s,\"args\":[",t->truncated?"true":"false");
    for(int i=0;i<6;i++)fprintf(out,"%s%llu",i?",":"",(unsigned long long)t->args[i]);
    fputs("]}\n",out);
}
int main(int argc,char **argv) {
    if(argc<4||strcmp(argv[2],"--")){fprintf(stderr,"usage: observer output -- executable args\n");return 2;}
    int fd=open(argv[1],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(fd<0){perror("observer output");return 2;}
    out=fdopen(fd,"w");setvbuf(out,NULL,_IOLBF,0);
    pid_t root=fork();if(root<0)return 2;
    if(!root){fclose(out);if(ptrace(PTRACE_TRACEME,0,0,0)<0)_exit(125);raise(SIGSTOP);execvp(argv[3],argv+3);_exit(127);}
    int status,root_status=1;
    if(waitpid(root,&status,0)<0||!WIFSTOPPED(status)){fclose(out);return 125;}
    long options=PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL;
    if(ptrace(PTRACE_SETOPTIONS,root,0,(void*)options)<0){kill(root,SIGKILL);fclose(out);return 125;}
    get(root);
    fprintf(out,"{\"sequence\":%lu,\"kind\":\"trace_started\",\"root_pid\":%d,\"time_ns\":%llu,\"backend\":\"ptrace-child-x86_64\"}\n",
        sequence++,root,(unsigned long long)now_ns());
    ptrace(PTRACE_SYSCALL,root,0,0);
    for(;;){
        pid_t pid=waitpid(-1,&status,__WALL);
        if(pid<0){if(errno==EINTR)continue;if(errno!=ECHILD)failures++;break;}
        struct thread *t=get(pid);if(!t){kill(pid,SIGKILL);failures++;continue;}
        if(WIFEXITED(status)||WIFSIGNALED(status)){
            fprintf(out,"{\"sequence\":%lu,\"kind\":\"process_exit\",\"pid\":%d,\"time_ns\":%llu}\n",sequence++,pid,(unsigned long long)now_ns());
            if(pid==root)root_status=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);
            t->pid=0;continue;
        }
        int sig=WSTOPSIG(status);unsigned int event=(unsigned int)status>>16;
        if(event==PTRACE_EVENT_FORK||event==PTRACE_EVENT_VFORK||event==PTRACE_EVENT_CLONE){
            unsigned long child=0;ptrace(PTRACE_GETEVENTMSG,pid,0,&child);get((pid_t)child);
            fprintf(out,"{\"sequence\":%lu,\"kind\":\"spawn\",\"pid\":%d,\"child_pid\":%lu,\"time_ns\":%llu}\n",sequence++,pid,child,(unsigned long long)now_ns());
        } else if(sig==(SIGTRAP|0x80)){
            struct trace_info info;memset(&info,0,sizeof(info));
            long size=ptrace(PTRACE_GET_SYSCALL_INFO,pid,sizeof(info),&info);
            if(size<0)failures++;else if(info.op==1)begin(t,&info);else if(info.op==2){end(t,info.data.exit.value);t->nr=-1;}
        }
        int deliver=(sig==SIGSTOP||sig==(SIGTRAP|0x80)||event)?0:sig;
        if(ptrace(PTRACE_SYSCALL,pid,0,(void*)(long)deliver)<0&&errno!=ESRCH)failures++;
    }
    fprintf(out,"{\"sequence\":%lu,\"kind\":\"trace_closed\",\"complete\":%s,\"errors\":%d,\"time_ns\":%llu}\n",
        sequence++,failures?"false":"true",failures,(unsigned long long)now_ns());
    if(fclose(out))return 126;
    return root_status;
}
