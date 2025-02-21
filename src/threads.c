#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void* thread_func(void* arg)
{
    void *a = malloc(8192);
    free(a);
	return NULL;
}

int main()
{
	int i;
	const int num_threads = 10000;
	pthread_t threads[num_threads];

	for (i = 0; i < num_threads; i++)
		pthread_create(&threads[i], NULL, thread_func, NULL);

	for (i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);

	return 0;
}
