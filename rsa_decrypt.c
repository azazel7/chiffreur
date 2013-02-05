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
	
	printf("[i] Allocation de memoire pour les fichiers\n");
	fichier = malloc( (taille + (16 - (taille%16))) * sizeof(unsigned char));//On genere une taille multiple de 16
	fichier_chiffre = malloc( (taille + (16 - (taille%16))) * sizeof(unsigned char));
	if(fichier == NULL || fichier_chiffre == NULL)
	{
		printf("[-] Erreur d'allocation : %d octet(s)\n", (taille + (16 - (taille%16))) * 2 * sizeof(unsigned char));
		return -1;
	}
	printf("[i] Lecture du fichier\n");
	fread(fichier, taille, 1, p_fichier);
	taille = (taille + (16 - (taille%16))); //On fixe la taille du tableau car la taille du fichier n'importe plus 
	//On génére la clee camellia
	printf("[i] Generation de la clee camellia\n");
	generer_clee(clee, 32);
	//on calcule le hash md5
	printf("[i] Calcule du hash md5 du fichier\n");
	md5_file( argv[1], md5);
	//On chiffre le contenu du fichier
	printf("[i] Chiffrement du fichier\n");
	camellia_setkey_enc( &camellia, clee, 256);
	camellia_crypt_cbc( &camellia, CAMELLIA_ENCRYPT, taille, IV, fichier, fichier_chiffre);
	//On chiffre la clee camellia
	printf("[i] Chiffrement de la clee camellia\n");
	chiffrer_rsa(clee, cryptogramme_clee ); //TODO
	//On ecrit le cryptogramme de la clee camellia
	printf("[i] Ouverture du fichier de sortie: %s\n", argv[2]);
	sortie = fopen(argv[2], "wb");
	if(sortie == NULL)
	{
		printf("[-] Erreur d'ouverture de %s\n", argv[2]);
		return -1;
	}
	printf("[i] Ecriture de la clee camellia chiffree\n");
	fwrite(cryptogramme_clee, RSA_TAILLE/8, 1, sortie); //TODO
	//On ecrit le hash md5
	printf("[i] Ecriture du hash md5 du fichier\n");
	fwrite(md5, 16, 1, sortie);
	//On ecrit les IV
	printf("[i] Ecriture des IV\n");
	fwrite(IV_svg, 16, 1, sortie);
	//On ecrit le fichier chiffre
	printf("[i] Ecriture du fichier chiffre\n");
	fwrite(fichier_chiffre, taille, 1, sortie);
	
	fclose(sortie);
	fclose(p_fichier);
}

void dechiffrer(unsigned char *fichier_chiffre, int taille)
{
	unsigned char clee_camellia[32] = {0};
	unsigned char IV[16] = {0};
	unsigned char md5_origine[16] = {0};
	unsigned char md5_claire[16] = {0};
	unsigned char sortie_rsa[
	//Allouer un tableau de taille - 4096/8 -16 - 16 pour le fichier clair
	unsigned char *fichier_claire = malloc(sizeof(unsigned char) * (taille - 40096/8 -16 -16));
	//recuperer cryptogramme clee camellia
	
	//recuperer md5
	//recuperer IV
	
	//dechiffrer clee camellia
	
	//dechiffrer fichier
	
	//calculer somme md5 du fichier claire
	
	//comparer les sommes md5
}
