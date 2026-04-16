#include <stdio.h>
#include <unistd.h>

int main(void)
{
	pid_t pid = fork();
	switch (pid)
	{
		case -1:
			fprintf(stderr, "fork error\n");
			return -1;
			break;
		case 0:
			printf("Child, PID = %d\n", getpid());
			break;
		default:
			printf("Parent, PID = %d\n", getpid());
	}
}