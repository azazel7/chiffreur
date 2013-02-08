#include <stdio.h>

void generer_clee(unsigned char *clee, int taille)
{
	int i;
	for(i = 0; i < taille; i++)
	{
		clee[i] = 84;
	}
	clee[taille - 1] = 0;
	
/*
	//Ouvrir /dev/random
	FILE* file_random = fopen("/dev/random", "rb");
	if(file_random == NULL)
	{
		int i;
		for(i = 0; i < taille; i++)
		{
			clee[i] = rand();
		}
	}
	else
	{
		fread(clee, sizeof(unsigned char), taille, file_random);
		fclose(file_random);
	}
	//Lire vers clee la taille
*/
}
