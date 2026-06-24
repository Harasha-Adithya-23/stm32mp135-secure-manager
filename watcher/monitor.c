#include <stdio.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <string.h>
#include <stdlib.h>


#define SIZE 4096


int main()
{
    int fd;
    int wd;

    char buffer[SIZE];                          // for file name


    fd = inotify_init();                        // inotfiy initialization

    if(fd < 0)
    {
        perror("inotify");
        return 1;
    }


    wd = inotify_add_watch(
            fd,
            "./incoming",
            IN_CLOSE_WRITE);                        // watcher created to watch the incoming folder


    if(wd < 0)
    {
        perror("watch");
        return 1;
    }


    printf("Secure Manager watching...\n");


    while(1)
    {

        int len = read(fd, buffer, SIZE);


        if(len <= 0)
            continue;



        struct inotify_event *event =
            (struct inotify_event *)buffer;



        if(event->len)
        {

            printf("Received: %s\n",
                    event->name);



            char filepath[256];


            snprintf(filepath,
                     sizeof(filepath),
                     "./incoming/%s",
                     event->name);



            /*
              only react to .bin
            */

			if(strstr(event->name, ".bin") ||
			   strstr(event->name, ".sig"))
			{

			    char binfile[256];
			    char sigfile[256];


			    if(strstr(event->name, ".bin"))
			    {
			        snprintf(binfile,
			                 sizeof(binfile),
			                 "./incoming/%s",
			                 event->name);


			        strcpy(sigfile, binfile);

			        sigfile[strlen(sigfile)-4]='\0';

			        strcat(sigfile,
			               ".sig");
			    }


			    else
			    {
			        snprintf(sigfile,
			                 sizeof(sigfile),
			                 "./incoming/%s",
			                 event->name);


			        strcpy(binfile, sigfile);

			        binfile[strlen(binfile)-4]='\0';

			        strcat(binfile,
			               ".bin");
			    }



			    if(access(binfile,F_OK)==0 &&
			       access(sigfile,F_OK)==0)
			    {

			        printf("Both files found\n");


			        char command[512];


			        snprintf(command,
			                 sizeof(command),
			                 "./secure_manager_host %s %s",
			                 binfile,
			                 sigfile);



			        printf("Launching verifier...\n");


			        system(command);

			    }
			}

        }
    }


    close(fd);

    return 0;
}
