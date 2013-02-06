#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "src/config.h"

#include "src/rsa.h"
#include "src/entropy.h"
#include "src/ctr_drbg.h"
#include "src/usage_camellia.h"
#include "src/camellia.h"
#include "src/clee_pub.h"

int main( int argc, char *argv[] )
{
	if(argc != 2)
	{
		printf("Usage: %s <fichier in> <fichier out>\n", argv[0]);
		printf("Structure du fichier: <clee camellia><md5 originel (16)><IV (16)><Fichier>\n");
		return 0;
	}
	unsigned char IV[16] = {0}, IV_svg[16] = {0};
	unsigned char md5[16] = {0};
	unsigned char clee[32] = {0};
	unsigned char cryptogramme_clee[RSA_TAILLE/8] = {0};
	unsigned char *fichier = NULL, *fichier_chiffre = NULL;
	FILE *p_fichier = NULL, *sortie = NULL;
	camellia_context camellia;
	unsigned int taille;
	printf("[i] Initialisation des IV\n");
	ret = 1;
	srand(time(NULL));
	for(ret = 0; ret < 16; ret++)
	{
		IV_svg[ret] = IV[ret] = rand();
	}
	ret = 1;
	//Argument, le fichier
	//Recuperer la clee camellia pour dechiffrer la clee rsa
	//dechiffre la clee public
	
	//On map le fichier en memoire
	printf("[i] Lecture de la taille du fichier %s\n", argv[1]);
	p_fichier = fopen(argv[1], "rb");
	if(p_fichier == NULL)
	{
		printf("[-] Erreur d'ouverture de %s\n", argv[1]);
		return -1;
	}
	printf("[i] Mesure de la taille du fichier %s\n", argv[1]);
	fseek(p_fichier, 0, SEEK_END);
	taille = ftell(p_fichier);
	rewind(p_fichier);
	if((taille - RSA_TAILLE/8 - 16 - 166)%16 != 0)
	{
		printf("[-] Erreur de taille. Pas de multiple de 16.\n");
	} 	
	printf("[i] Allocation de memoire pour les fichiers\n");
	fichier = malloc(taille * sizeof(unsigned char));//On genere le fichier  
	fichier_dechiffre = malloc((taille - RSA_TAILLE/8 - 16 - 16) * sizeof(unsigned char));
	if(fichier == NULL || fichier_dechiffre == NULL)
	{
		printf("[-] Erreur d'allocation : %d octet(s)\n", taille * sizeof(unsigned char));
		return -1;
	}
	printf("[i] Lecture du fichier\n");
	fread(fichier, taille, 1, p_fichier);
	//TODO Associer à dechiffrer
}

void dechiffrer(unsigned char *fichier_chiffre, int taille)
{
	unsigned char clee_camellia[32] = {0};
	unsigned char IV[16] = {0};
	unsigned char md5_origine[16] = {0};
	unsigned char md5_claire[16] = {0};
	unsigned char cryptogramme_camellia[RSA_TAILLE/8] = {0};
	//Allouer un tableau de taille - 4096/8 -16 - 16 pour le fichier clair
	unsigned char *fichier_claire = malloc(sizeof(unsigned char) * (taille - RSA_TAILLE/8 -16 -16));
	//recuperer cryptogramme clee camellia
	
	//recuperer md5
	//recuperer IV
	
	//dechiffrer clee camellia
	
	//dechiffrer fichier
	
	//calculer somme md5 du fichier claire
	
	//comparer les sommes md5
}
