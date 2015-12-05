//compile with flag -Wno-char-subscripts

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "rulify.h"


int main(int argc, char *argv[])
{

if (argc == 1)
    {
        fprintf (stderr,"\nRulify - A Rule Processor, part of the Unified List Manager (ULM) project unifiedlm.com\n\n");
        fprintf (stderr,"usage: %s -i infile -r rulefile [options]\n\nOptions:\n\t-v\tVerify rules (Shows valid/invalid rules)\n\t\tOmit -i switch for Stdin\n",argv[0]);
        return -1;
    }

        char *ivalue = NULL;
        char *rvalue = NULL;
        char *ovalue = NULL;
        int index;
        int check = 0;
        int c;

       opterr = 0;

       while ((c = getopt (argc, argv, "fpvi:r:o:")) != -1)
         switch (c)
           {
           case 'i':
             ivalue = optarg;
             break;
           case 'r':
             rvalue = optarg;
             break;
           case 'o':
             ovalue = optarg;
             break;
           case 'v':
             check = 1;
             break;
           case '?':
             if (optopt == 'i' || optopt == 'r')
               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
             else if (isprint (optopt))
               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
             else
               fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
             return 1;
           default:
             abort ();
           }

        for (index = optind; index < argc; index++)
        {
            fprintf (stderr,"index is %d\n",index);
            fprintf (stderr,"Non-option argument %s\n", argv[index]);

        }



    if (rvalue == NULL)
    {
        fprintf (stderr,"Please specify -r rulefile\n");
        exit(1);
    }

    char ruleFile[BUFSIZ];
    sprintf (ruleFile, "%s", rvalue);
    FILE *readStream = fopen(ruleFile, "rb");
    if (ruleFile == NULL)
    {
        fprintf (stderr,"Error opening rule file %s\n",ruleFile);
        exit(1);
    }


    char inFile[BUFSIZ];
    FILE * inputFile;
    if (ivalue == NULL && check ==0)
    {
        fprintf (stderr,"No -i inputfile specified, reading from stdin\n");
        inputFile = stdin;
    }
    else
    {
        sprintf (inFile, "%s", ivalue);
        inputFile = fopen(inFile, "rb");
        if (inFile == NULL)
        {
            fprintf (stderr,"Error opening file %s\n",inFile);
            exit(1);
        }
    }

    char outFile[BUFSIZ];
    FILE * outputFile;
    if (ovalue == NULL)
    {
        outputFile = stdout;
    }
    else
    {

        sprintf(outFile, "%s", ovalue);
        outputFile = fopen(outFile,"wb");
        if (outFile == NULL)
        {
            fprintf (stderr,"Error opening file to write %s\n",outFile);
            exit(1);
        }

    }

    unsigned int sz = 0; //Variable to hold size of file
    fseek(readStream, 0L, SEEK_END); //Jump to EOF
    sz = ftell(readStream); //Grab the bytes
    fseek(readStream, 0L, SEEK_SET); //Reset back to start of file
    char * RuleFileBuffer = (char*) malloc(sz+1);
    fread(RuleFileBuffer, sizeof(char), sz, readStream); //This is bad practice and will lead to errors if file is too large, should allocate in chunks
    fclose(readStream);
    unsigned int readItems = 0;
    //Count where file actually starts excluding blanks
    unsigned int ActualStart = 0;
    unsigned int i = 0;
    for ( i = 0; i< sz; i++)
    {
        if ((int)RuleFileBuffer[i] != 10 && (int)RuleFileBuffer[i] != 13 && (int)RuleFileBuffer[i] != 0)
        {
            ActualStart = i;
            break;
        }
    }
    //Count where we actually need to end excluding trailing blank lines
    unsigned int ActualEnd = 0;
    for (i = sz; i> 0; i--)
    {
        if ((int)RuleFileBuffer[i] != 10 && (int)RuleFileBuffer[i] != 13 && (int)RuleFileBuffer[i] != 0)
        {
            ActualEnd = sz+1;
            break;
        }
    }
    RuleFileBuffer[sz] = '\0';

    for ( i = ActualStart; i< ActualEnd; i++)
    {
        if ((int)RuleFileBuffer[i] == 10 || (int)RuleFileBuffer[i] == 13)
        {
            RuleFileBuffer[i] = '\0';
            if ((int)RuleFileBuffer[i+1] != 10 && (int)RuleFileBuffer[i+1] != 13 && (int)RuleFileBuffer[i+1] != 0)
            {
                readItems++;
            }
        }
        else if((int)RuleFileBuffer[i] == 0)
        {
            readItems++;
        }
    }


initMaps();

    char **RuleMap = (char**) malloc(readItems * sizeof(char*));
    int trigger = 1;
    unsigned int counter = 0;

    for ( i = ActualStart; i< ActualEnd ; i++)
    {

        if ((int)RuleFileBuffer[i] == 0)
        {
            trigger = 1;
        }
        else if (trigger ==1 && RuleFileBuffer[i] !=0) //Added additional gate
        {

            trigger = 0;
            if (validateRule(RuleFileBuffer+i))
            {
                RuleMap[counter] = RuleFileBuffer+i;
                counter ++;
                if (check == 1)
                {
                    printf("Validated rule:%s\n" ,RuleFileBuffer+i);
                }

            }
            else
            {
                if (check == 1)
                {
                    printf("Invalid Rule:%s\n",RuleFileBuffer+i);
                }
            }
        }
    }

    if (check == 1)
    {
        free(RuleMap);
        exit(1);
    }

    fprintf(stderr,"Number of validated rules: %u\n",counter);
    rule_struct ruleProp[1];
    ruleProp[0].numRules = counter;
    ruleProp[0].RuleFileBuffer = RuleFileBuffer;
    ruleProp[0].RuleMap = RuleMap;

    ruleProp[0].RuleLen = (size_t*) malloc(counter * sizeof(size_t)); //Allocate space for the rule lengths

    for (i = 0; i< counter;i++) //Pre-calc the rule lengths to save time for the loops in the RunRule code
    {
        ruleProp[0].RuleLen[i] = strlen(RuleMap[i]);
    }

    char out[BUFSIZ];
    char line_buff[BUFSIZ];
    char * p;

    while (fgets(line_buff, sizeof line_buff,inputFile) != NULL) {
        p = line_buff + strlen(line_buff) - 1;
        if (*p == '\n') *p = '\0';
        if ((p != line_buff) && (*--p == '\r')) *p = '\0';

            size_t i = 0;
            for (i =0; i<ruleProp[0].numRules; i++)
            {

                RunRule(ruleProp,line_buff,strlen(line_buff),out,i);
                if (strlen(out)!= 0 )
                {
                    fprintf(outputFile,"%s %s\n",out,ruleProp[0].RuleMap[i]);
                }
            }

    }

    fclose(outputFile);
    return 0;
}
