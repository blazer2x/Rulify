#ifndef RULIFY_H
#define RULIFY_H

typedef struct{
    unsigned long numRules;     //Number of rules for this set
    char** RuleMap;              //Pointers mapping to each rule
    char * RuleFileBuffer;       //Buffer that holds all the unmapped
    size_t * RuleLen;
    size_t RuleOutReturnLen;
    }rule_struct;

int validateRule(char * rule_buff);
int RunRule(rule_struct * ruleProp, char * inString, size_t inStringLen, char * outString, unsigned long ruleNum);
void initMaps();
#endif