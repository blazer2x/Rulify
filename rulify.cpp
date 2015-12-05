/*
Heavy speed focused optimizations will be made to this rulify including

    a/ Removal of incompatible hashcat/jtr/isp rules
    b/ Early escape detection in rules
    c/ Attempt to remove/minimize all calls to string functions eg strlen, strcpy instead use memory based functions
    d/ Optimize len tracking through strict len tracking within rules to prevent unnecessary strlen calls
    e/ Optimize fast skipping by jumping the pointer along the rule instead of moving along each rule call
    f/ Since no strlen calls will be invoked the NULL terminator will be applied at the final step as we don't need it
*/

#define MAXLINE '100'
#include <stdio.h>
#include <string.h>
#include <stdlib.h> //Random
#include <ctype.h> //To lower

#include "rulify.h"
//Rules ripped from hashcat/ppro/jtr
#define RULE_OP_MANGLE_NOOP             ':' // does nothing
#define RULE_OP_MANGLE_LREST            'l' // lower case all chars
#define RULE_OP_MANGLE_UREST            'u' // upper case all chars
#define RULE_OP_MANGLE_LREST_UFIRST     'c' // lower case all chars, upper case 1st
#define RULE_OP_MANGLE_UREST_LFIRST     'C' // upper case all chars, lower case 1st
#define RULE_OP_MANGLE_TREST            't' // switch the case of each char
#define RULE_OP_MANGLE_TOGGLE_AT        'T' // switch the case of each char on pos N
#define RULE_OP_MANGLE_REVERSE          'r' // reverse word
#define RULE_OP_MANGLE_DUPEWORD         'd' // append word to itself
#define RULE_OP_MANGLE_DUPEWORD_TIMES   'p' // append word to itself N times
#define RULE_OP_MANGLE_REFLECT          'f' // reflect word (append reversed word)
#define RULE_OP_MANGLE_ROTATE_LEFT      '{' // rotate the word left.  ex: hello -> elloh
#define RULE_OP_MANGLE_ROTATE_RIGHT     '}' // rotate the word right. ex: hello -> ohell
#define RULE_OP_MANGLE_APPEND           '$' // append char X
#define RULE_OP_MANGLE_PREPEND          '^' // prepend char X
#define RULE_OP_MANGLE_DELETE_FIRST     '[' // delete first char of word
#define RULE_OP_MANGLE_DELETE_LAST      ']' // delete last char of word
#define RULE_OP_MANGLE_DELETE_AT        'D' // delete char of word at pos N
#define RULE_OP_MANGLE_EXTRACT          'x' // extract X chars of word at pos N
#define RULE_OP_MANGLE_OMIT             'O' // OMIT X chars of word at pos N
#define RULE_OP_MANGLE_INSERT           'i' // insert char X at pos N
#define RULE_OP_MANGLE_OVERSTRIKE       'o' // overwrite with char X at pos N
#define RULE_OP_MANGLE_TRUNCATE_AT      '\''// cut the word at pos N
#define RULE_OP_MANGLE_REPLACE          's' // replace all chars X with char Y
#define RULE_OP_MANGLE_PURGECHAR        '@' // purge all instances of char X
#define RULE_OP_MANGLE_DUPECHAR_FIRST   'z' // prepend first char of word to itself N times. ex: hello -> hhello
#define RULE_OP_MANGLE_DUPECHAR_LAST    'Z' // append last char of word to itself N times.   ex: hello -> helloo
#define RULE_OP_MANGLE_DUPECHAR_ALL     'q' // duplicate all chars. ex: hello -> hheelllloo
#define RULE_OP_MANGLE_EXTRACT_MEMORY   'X' // insert substring delimited by N and M into current word at position I
#define RULE_OP_MANGLE_APPEND_MEMORY    '4' // insert the word saved by 'M' at the end of current word
#define RULE_OP_MANGLE_PREPEND_MEMORY   '6' // insert the word saved by 'M' at the beginning of current word
#define RULE_OP_MEMORIZE                'M' // memorize the current word

//End standard rules

//Additional rules not found in ppro/hm/hashcat/jtr
#define RULE_OP_REPLACE_SINGLE_LEFT     'S' // replace a single instance of X with Y from the left SXY
#define RULE_OP_REPLACE_SINGLE_RIGHT    'W' // replace a single instance of X with Y from the right RXY
//End additional rules

//Extra memory functions
#define RULE_MEM_TOGGLE                 '0' // Toggle memory mode (rules will be applied to memory, make sure it is untoggled)
#define RULE_MEM_CUT_BLOCK              'v' // move a block from pos X to Y into memory
#define RULE_MEM_COPY_BLOCK             'm' // copy a block from pos X to Y into memory (can use X mode instead)
#define RULE_MEM_INSERT                 'I' // Inserts memory into line at pos X (can use X mode instead)
#define RULE_MEM_OVERWRITE              'P' // Overwrites line with memory at pos X
//End extra memory functions

//Extra Rules from hashcat
#define RULE_OP_SWAPFRONT               'k' //Swap first two characters
#define RULE_OP_SWAPBACK                'K' //Swap last two characters
#define RULE_OP_SWAPCHARS               '*' //Swaps character X with Y
#define RULE_OP_BITWISEL                'L' //Bitwise rotate left
#define RULE_OP_BITWISER                'R' //Birwise rotate right
#define RULE_OP_CLONEFORWARD            '.' //Replaces character @ N with value @ N plus 1
#define RULE_OP_CLONEBACKWARD           ',' //Replaces character @ N with value @ N minus 1
#define RULE_OP_ASCIIUP                 '+' //Increment character @ N by 1 ascii value
#define RULE_OP_ASCIIDOWN               '-' //Decrement character @ N by 1 ascii value
#define RULE_OP_CLONEBLOCKF             'y' //Duplicates first block of N characters
#define RULE_OP_CLONEBLOCKR             'Y' //Duplicates last block  N characters
#define RULE_OP_TITLE                   'E' //Lower case the whole line, then upper case the first letter and every letter after a space
//End Extra Rules


//Hashcat Rejection rules (can be used with logic IF)
#define RULE_GATE_LESS                  '<' //Reject plains of length greater than N
#define RULE_GATE_GREATER               '>' //Reject plains of length less than N
#define RULE_GATE_CONTAIN               '!' //Reject plains which contain char X
#define RULE_GATE_NOT_CONTAIN           '/' //Reject plains which do not contain char X
#define RULE_GATE_FIRSTCHAR             '(' //Start with char (X thi
#define RULE_GATE_LASTCHAR              ')' //Ends with char )X
#define RULE_GATE_EQUALSCHAR_AT         '=' //Reject plains which do not have char X at position N
#define RULE_GATE_CONTAINS_NUM          '%' //Reject plains which do not have char X at position N
#define RULE_GATE_MEM_CONTAINS          'Q' //Reject plains where the memory saved matches current word

char mapstring[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; //Used to map the chars to positions
char singleR[] = "LR:lucCtrdf[]{}qM46Q~E0\""; //Rules with single char
char DoubleR[] = "Tp$^DzZ@\\<>!/()IO"; //Rules with double char
char TripleR[] = "ios=mvSW"; //Rules with three chars
char QuadR[] = "XF"; //Rules with quadruple char
int RuleJump[100];
int LongJump = 0;
//Logical operators
char logicOPs[] = "<>!/()=Q";
int isLogical[127] = {0};
int RuleOPs[127] = {0};
char toggleMap[BUFSIZ];
int charMap[256]; //Holds the ASCII rep of luds for those sets
//Used to generate the correct positional maps to map the chars into positions

int posMap[127];
//Self explanatory
char numbers[] = "0123456789";
char symbols[] = "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ ]";
char lower[] = "abcdefghijklmnopqrstuvwxyz";
char upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char all[] = "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/ ]0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

char uspecial[] = "ÀÁÂÄÃÅÆÇÐÈÉÊËÌÍÎÏÑÒÓÔÖÕØŒŠÙÛÚÜÝŸŽÞ";
char lspecial[] = "àáâäãåæçÐèéêëìíîïñòóôöõøœšùûúüýÿžþ";


int randomize(int min, int max){
   return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}


int remSpace(char * buffer, int pos)
{
    if (buffer[pos+1] == 32)
    {
        strcpy(buffer+pos+1,buffer+pos+2);
        return 1;
    }
    return 0;
}
//Routine which gets the pointer to the read rule
int validateRule(char * rule_buff)
{
    int rule_len = strlen(rule_buff);  //Holds the length (chars) of the rule
    int u = 0; //Variable we use to process loops

    int skip = 0; //Denotes whether a skip is needing as some rules contain more than 1 character (2,3,4)
    int validMap[BUFSIZ]; //Holds the mapping of position to RulePos
    int mem_mode = 0;
    int rand_mode = 0;
    //Initialize the map (position to > RulePos [0-Z]) to zero
    for (u = 0; u< BUFSIZ; u++)
    {
        validMap[u] = 0;
    }

    //Flag the positions which we know will be valid to one [0-Z] 62 positions
    for (u = 0; u< sizeof(mapstring); u++)
    {
        validMap[(int)mapstring[u]] = 1;
    }

    //Start looping through the characters in the rule and process
    for (u = 0; u<rule_len; u++)
    {
        if (skip !=0 )
        {
            skip--; //If a skip is issues, simply decrease the skip counter and do not process (this is needed since some rules contain more than a single char)
            continue;
        }
        if (rule_buff[u] == ' ') //The rule processor ignores space characters (treats them as blank so just skip them)
        {
          memmove(rule_buff+u,rule_buff+u+1,rule_len-u);
          rule_len--;
          u--;
            continue;
        }

        if (rule_buff[u] == 34) //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            continue;
        }
        if (rule_buff[u] == '`') //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            continue;
        }

        if (rule_buff[u] == ';') //The rule processor ignores space characters (treats them as blank so just skip them)
        {
            if (rand_mode !=1)
            {
                return 0;
            }
            rand_mode = !rand_mode;
            continue;
        }

        else if ( rule_buff[u] == RULE_OP_MANGLE_EXTRACT_MEMORY)
        {
            skip = 3;
            if (rule_len-(u+1) < 3)
            {
                return 0;
            }
            int val = rule_buff[u+1] - '0';
            if (val == 0 || validMap[rule_buff[u+1]] == 0)
            {

                return 0;
            }
            if (validMap[rule_buff[u+2]] == 0 || validMap[rule_buff[u+3]] == 0)
            {
                return 0;
            }
        }
        else if ( rule_buff[u] == RULE_MEM_COPY_BLOCK || rule_buff[u] == RULE_MEM_CUT_BLOCK)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                    return 0;
            }
            int val = rule_buff[u+2] - '0';
            if (val == 0 || validMap[rule_buff[u+2]] == 0)
            {
                    return 0;
            }
        }
        else if ( rule_buff[u] == RULE_OP_MANGLE_EXTRACT)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }
            int val = rule_buff[u+2] - '0';
            if (val == 0 || validMap[rule_buff[u+2]] == 0)
            {
                return 0;
            }
        }

        else if (rule_buff[u] == RULE_MEM_INSERT  || rule_buff[u] == RULE_MEM_OVERWRITE || rule_buff[u] == RULE_OP_MANGLE_TOGGLE_AT || rule_buff[u] == RULE_OP_MANGLE_DELETE_AT)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }

        }
        else if (rule_buff[u] == RULE_OP_MANGLE_DUPEWORD_TIMES
            || rule_buff[u] == RULE_OP_MANGLE_TRUNCATE_AT || rule_buff[u] == RULE_OP_CLONEBACKWARD || rule_buff[u] == RULE_OP_CLONEFORWARD
            || rule_buff[u] == RULE_OP_ASCIIUP || rule_buff[u] == RULE_OP_ASCIIDOWN || rule_buff[u] == RULE_OP_CLONEBLOCKF || rule_buff[u] == RULE_OP_CLONEBLOCKR
            || rule_buff[u] == RULE_GATE_LESS || rule_buff[u] == RULE_GATE_GREATER || rule_buff[u] == RULE_OP_BITWISEL|| rule_buff[u] == RULE_OP_BITWISER)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }

            if (rule_buff[u] == RULE_OP_CLONEBACKWARD) //Cannot be 0 since we can't go backwards
            {
                if (rule_buff[u+1] == 0)
                {
                    return 0;
                }
            }
        }
        else if( rule_buff[u] == RULE_OP_MANGLE_INSERT  || rule_buff[u] == RULE_OP_MANGLE_OVERSTRIKE || rule_buff[u] == RULE_GATE_EQUALSCHAR_AT )
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_MANGLE_DUPECHAR_FIRST || rule_buff[u] == RULE_OP_MANGLE_DUPECHAR_LAST)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
            int val = rule_buff[u+1] - '0';
            if (val == 0 || validMap[rule_buff[u+1]] == 0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_MANGLE_REPLACE || rule_buff[u] == RULE_OP_REPLACE_SINGLE_LEFT  || rule_buff[u] == RULE_OP_REPLACE_SINGLE_RIGHT)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {
                return 0;
            }
            if (rule_buff[u+1] - rule_buff[u+2]==0)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_MANGLE_APPEND || rule_buff[u] == RULE_OP_MANGLE_PREPEND || rule_buff[u] == RULE_OP_MANGLE_PURGECHAR
                 || rule_buff[u] == RULE_GATE_FIRSTCHAR || rule_buff[u] == RULE_GATE_LASTCHAR || rule_buff[u] == RULE_GATE_CONTAIN
                 || rule_buff[u] == RULE_GATE_NOT_CONTAIN)
        {
            skip = 1;
            if (rule_len-(u+1) < 1)
            {
                return 0;
            }
        }
        else if (rule_buff[u] == RULE_OP_SWAPCHARS)
        {
            skip = 2;
            if (rule_len-(u+1) < 2)
            {

                return 0;
            }
            if (validMap[rule_buff[u+1]] == 0)
            {

                return 0;
            }

            if (validMap[rule_buff[u+2]] == 0)
            {

                return 0;
            }

        }
        else if (rule_buff[u] == RULE_OP_MANGLE_NOOP || rule_buff[u] == RULE_OP_MANGLE_LREST || rule_buff[u] == RULE_OP_MANGLE_UREST
                 || rule_buff[u] == RULE_OP_MANGLE_LREST_UFIRST || rule_buff[u] == RULE_OP_MANGLE_UREST_LFIRST
                 ||rule_buff[u] == RULE_OP_MANGLE_TREST || rule_buff[u] == RULE_OP_MANGLE_REVERSE
                 || rule_buff[u] == RULE_OP_MANGLE_DUPEWORD || rule_buff[u] == RULE_OP_MANGLE_REFLECT
                 || rule_buff[u] == RULE_OP_MANGLE_ROTATE_LEFT || rule_buff[u] == RULE_OP_MANGLE_ROTATE_RIGHT
                 || rule_buff[u] == RULE_OP_MANGLE_DELETE_FIRST || rule_buff[u] == RULE_OP_MANGLE_DELETE_LAST
                 || rule_buff[u] == RULE_OP_MANGLE_EXTRACT_MEMORY || rule_buff[u] == RULE_OP_MANGLE_APPEND_MEMORY
                 || rule_buff[u] == RULE_OP_MANGLE_PREPEND_MEMORY || rule_buff[u] ==  RULE_OP_MEMORIZE
                 || rule_buff[u] == RULE_OP_SWAPFRONT || rule_buff[u] == RULE_OP_SWAPBACK || rule_buff[u] == RULE_GATE_MEM_CONTAINS
                 || rule_buff[u] == RULE_OP_TITLE || rule_buff[u] == RULE_OP_MANGLE_DUPECHAR_ALL )
                {}
        else if ( rule_buff[u] == RULE_MEM_TOGGLE)
        {
            mem_mode = !mem_mode;
        }
        else //If nothing matched then fail the verification
        {
            return 0;
        }
    }

    if (mem_mode  == 1 || rand_mode == 1) //Ensure the user actually untoggled the mem_editor or closed the random function
    {
        return 0;
    }

    return 1;
}

void initMaps()
{
    int i = 0;
        //Map the logical operators
    for (i = 0; i<sizeof(logicOPs); i++)
    {
        isLogical[logicOPs[i]] = 1; //Mark the logical Operators
    }

    for (i = 0; i<sizeof(singleR); i++)
    {
        RuleOPs[singleR[i]] = 1; //Single
    }
    for (i = 0; i<sizeof(DoubleR); i++)
    {
        RuleOPs[DoubleR[i]] = 2; //Double
    }
    for (i = 0; i<sizeof(TripleR); i++)
    {
        RuleOPs[TripleR[i]] = 3; //Triple
    }
    for (i = 0; i<sizeof(QuadR); i++)
    {
        RuleOPs[QuadR[i]] = 4; //Quad
    }
    //End Mapping Operations

    for (i = 0; i<62; i++)
    {
        posMap[mapstring[i]] = i;
    }

    for (i = 0; i<sizeof(lower)-1; i++)
    {
        charMap[lower[i]] = 108;
    }
    for (i = 0; i<sizeof(upper)-1; i++)
    {
        charMap[upper[i]] = 117;
    }
    for (i = 0; i<sizeof(numbers)-1; i++)
    {
        charMap[numbers[i]] = 100;
    }
    for (i = 0; i<sizeof(symbols)-1; i++)
    {
        charMap[symbols[i]] = 115;
    }

    //Initialize the full map
    for (i = 0; i<BUFSIZ;i++)
    {
        toggleMap[i] = i;
    }
    //Map the reverse toggles
    for (i = 0; i< sizeof(lower) ;i++)
    {
        toggleMap[lower[i]] = upper[i];
        toggleMap[upper[i]] = lower[i];
    }
    for (i = 0; i<sizeof(uspecial); i++)
    {
        toggleMap[uspecial[i]] = lspecial[i];
        toggleMap[lspecial[i]] = uspecial[i];
    }
}

int skipCalc(char** RuleMap, int ruleNum, int offset)
{
    int calc = 0;
    while (1)
        {
            if (RuleMap[ruleNum][offset]==34) break;
            calc+= RuleOPs[RuleMap[ruleNum][offset]];
            offset += RuleOPs[RuleMap[ruleNum][offset]];
        }
    return calc;
}

int markRules(char** RuleMap, int ruleNum, int offset)
{
    int qt_counter = 0;
    int qt_flag = 0;
    int initial_offset = offset; //Holds the value we started at so we can calculate the actual offset rather than the position
    while (1)
        {
            if (RuleMap[ruleNum][offset]==59)
            {
                LongJump = offset;
                break;
            }
            if (RuleMap[ruleNum][offset]==34)
            {

                qt_flag = !qt_flag;
                if (qt_flag)
                {
                    qt_counter ++;
                    RuleJump[qt_counter] = (offset-initial_offset)+2;
                }
                else
                {
                    offset ++;
                    continue;
                }

            }
            offset += RuleOPs[RuleMap[ruleNum][offset]];
        }
    return qt_counter;
}

int RunRule(rule_struct * ruleProp, char * inString, size_t inStringLen, char * outString, unsigned long ruleNum)
{

    char rule_temp[BUFSIZ];     //Used as a temporary storage for some functions
    char rule_mem[BUFSIZ];     //Used to memorize the line
    char line_toggle[BUFSIZ];  //Backup for memory toggling

    int skipRule = 0;
    long line_len = 0;
    long mem_len =0;
    int mem_mode = 0;;
    skipRule = 0;
    unsigned long i = 0;
    int x , k;

    {
        memcpy(outString,inString,inStringLen);
        line_len = inStringLen;
        i =0 ;
        while(i< ruleProp[0].RuleLen[ruleNum])//Optimizaion here, we can pre-cache strlen
        {

            if (line_len == 0)
                break;


            if (skipRule == 1)
                break;

            switch (ruleProp[0].RuleMap[ruleNum][i])
            {

                case RULE_OP_MANGLE_APPEND:
                {
                    while(ruleProp[0].RuleMap[ruleNum][i] == RULE_OP_MANGLE_APPEND)
                    {
                        outString[line_len] = (ruleProp[0].RuleMap[ruleNum][i+1]);
                        line_len ++;
                        i +=2;
                    }

                    break;
                }

                case RULE_OP_MANGLE_TOGGLE_AT:
                {
                    if (posMap[ruleProp[0].RuleMap[ruleNum][i+1]] > line_len)
                        {  i+=2;
                            continue;}
                    int pos = 0;
                    pos = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    outString[pos] = toggleMap[outString[pos]];
                    i +=2;
                    break;
                }
                case RULE_MEM_COPY_BLOCK:
                {

                    int ilen = 0;
                    int start = 0;

                    start = (ruleProp[0].RuleMap[ruleNum][i+1]-'0');
                    ilen = (ruleProp[0].RuleMap[ruleNum][i+2]-'0');

                    if (start+ilen > line_len) {
                          i+=3;
                            continue;}
                    memcpy(rule_mem,outString+start,ilen);
                    mem_len = ilen;
                    i +=3;
                    break;
                }
                case RULE_MEM_CUT_BLOCK:
                {

                    int ilen = 0;
                    int start = 0;

                    start = (ruleProp[0].RuleMap[ruleNum][i+1]-'0');
                    ilen = (ruleProp[0].RuleMap[ruleNum][i+2]-'0');

                    if (start+ilen > line_len) {  i+=3;
                            continue;}
                    memcpy(rule_mem,outString+start,ilen);
                    mem_len = ilen;
                    memcpy(outString+start,outString+start+ilen,line_len-start-ilen);

                    line_len -= ilen;
                    i +=3;
                    break;
                }
                case RULE_MEM_INSERT://optimizae here please
                {

                    if (posMap[ruleProp[0].RuleMap[ruleNum][i+1]] > line_len)
                    {   i+=2;
                        continue;}
                    memcpy(rule_temp,outString,line_len);
                    int value = 0;
                    value =  posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    memcpy(outString+value,rule_mem,mem_len);
                    memcpy(outString+value+mem_len,rule_temp+value,line_len-value);
                    line_len +=mem_len;
                    i =+2;
                    break;
                }
                case RULE_MEM_OVERWRITE:
                {

                    if ( posMap[ruleProp[0].RuleMap[ruleNum][i+1]] > line_len)
                    {   i+=2;
                        continue;}
                    int value= 0;
                    value = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    memcpy(outString+value,rule_mem,mem_len);
                    line_len += value;
                    i +=2;
                    break;
                }
                case RULE_OP_MANGLE_TREST:
                {
                    int b = 0;
                    for (b= 0; b<line_len; b++)
                    {
                        outString[b] = toggleMap[outString[b] ];
                    }
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_REPLACE:
                {

                    char match = ruleProp[0].RuleMap[ruleNum][i+1];
                    char write = ruleProp[0].RuleMap[ruleNum][i+2];
                    int b = 0;

                    for (b = 0;b<line_len; b++)
                    {
                        if (outString[b] == match)
                        {
                            outString[b] = write;
                        }
                    }
                    i +=3;
                    break;
                }
                case RULE_OP_REPLACE_SINGLE_LEFT:
                {

                    char match = 0;
                    char write = 0;
                    match = ruleProp[0].RuleMap[ruleNum][i+1];
                    write = ruleProp[0].RuleMap[ruleNum][i+2];

                    int b = 0;

                    for (b = 0;b<line_len; b++)
                    {
                        if (outString[b] == match)
                        {
                            outString[b] = write;
                            break;
                        }
                    }

                    i+=3;
                    break;
                }
                case RULE_OP_REPLACE_SINGLE_RIGHT:
                {
                    char match = 0;
                    char write = 0;
                    match = ruleProp[0].RuleMap[ruleNum][i+1];
                    write = ruleProp[0].RuleMap[ruleNum][i+2];

                    int b = 0;
                    for (b = line_len-1;b>-1; b--)
                    {
                        if (outString[b] == match)
                        {
                            outString[b] = write;
                            break;
                        }
                    }
                    i+=3;
                    break;
                }
                case RULE_OP_MANGLE_EXTRACT:
                {
                    //Updated to reflect changes
                    int ilen = posMap[ruleProp[0].RuleMap[ruleNum][i+2]];
                    int start = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    if (start > line_len)
                    {
                        i+=3;
                        break;
                    }

                    if (start+ilen > line_len) //Do not use absolute, fall back to maximum
                        {
                            ilen = line_len-start;
                        }

                    memmove(outString,outString+start,ilen);
                    line_len = ilen;
                    i +=3;
                    break;
                }
                case RULE_OP_MANGLE_OMIT:
                {
                    int ilen = posMap[ruleProp[0].RuleMap[ruleNum][i+2]];
                    int start = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    if (start+ilen > line_len) {  i+=3;
                            continue;}

                    memmove(outString,outString+start+ilen,line_len-start-ilen);
                    line_len -= ilen;
                    i +=3;
                    break;
                }
                case RULE_OP_MANGLE_PURGECHAR:
                {
                    //skip =1;
                    int b = 0;
                    char needle = ruleProp[0].RuleMap[ruleNum][i+1];
                    for (b = 0; b<line_len; b++)
                    {
                        if (outString[b] == needle)
                        {
                            memmove(outString+b,outString+b+1,line_len-1);
                            line_len--;
                        }

                    }
                    i+=2;
                    break;
                }


                case RULE_OP_MANGLE_EXTRACT_MEMORY:
                {
                    //skip = 3;

                    int pos = ruleProp[0].RuleMap[ruleNum][i+3] - '0';
                    int ilen = ruleProp[0].RuleMap[ruleNum][i+2] - '0';
                    int start = ruleProp[0].RuleMap[ruleNum][i+1] - '0';

                    if (pos > line_len) {  i+=3;
                            continue;}
                    if (start + ilen >strlen(rule_mem)) {  i+=3;
                        continue;}
                    memcpy(rule_temp,outString,line_len);
                    memcpy(outString+pos+ilen,rule_temp+pos,line_len-pos);
                    memcpy(outString+pos,rule_mem+start,ilen);
                    line_len += ilen;
                    i+=4;
                    break;
                }

                case RULE_OP_MANGLE_APPEND_MEMORY:
                {
                    memcpy(outString+line_len,rule_mem,mem_len);
                    line_len += mem_len;
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_PREPEND_MEMORY:
                {
                    memcpy(rule_temp,outString,line_len);
                    memcpy(outString+mem_len,rule_temp,line_len);
                    memcpy(outString,rule_mem,mem_len);
                    line_len += mem_len;
                    i++;
                    break;
                }

                case RULE_OP_MEMORIZE:
                {
                    memcpy(rule_mem,outString,line_len);
                    mem_len = line_len;
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_ROTATE_LEFT:
                {
                    int b = 0;
                    k = 1;
                    while (ruleProp[0].RuleMap[ruleNum][i+1] == RULE_OP_MANGLE_ROTATE_LEFT )
                    {
                        k++; i++;
                    }

                    if (line_len ==1) //Early exit if there is 1 char to rotate
                    {
                        i++;
                        break;
                    }

                    if (k > line_len) //Number of rotates is greater than line_len, lets calculate the offset using remainder method
                    {
                        x = k % line_len;
                    }
                    else
                    {
                        x = k;
                    }

                    if (x == 0)
                    {
                        i++;
                        break;
                    }

                    for (k = 0;k<x;k++) //Move the first section to the end of the string
                    {
                        outString[line_len+k] = outString[k];
                    }
                    for (k = x;k<line_len+x;k++) //Shift everything back to starting spot
                    {
                        outString[b] = outString[k];
                        b++;
                    }
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_ROTATE_RIGHT:
                {
                    k = 1;
                    while (ruleProp[0].RuleMap[ruleNum][i+1] == RULE_OP_MANGLE_ROTATE_RIGHT )
                    {
                        k++; i++;
                    }
                    if (line_len ==1) //Early exit if there is 1 char to rotate
                    {
                        i++;
                        break;
                    }
                    if (k >= line_len) //Number of rotates is greater than line_len, lets calculate the offset using remainder method
                    {
                        x = k % line_len;
                    }
                    else
                    {
                        x = k;
                    }

                    if (x == 0)
                    {
                        i++;
                        break;
                    }

                    for (k = 0;k<line_len-x;k++) //Move what is needed to the end
                    {
                        outString[line_len+k] = outString[k];
                    }
                    for (k = 0; k<line_len; k++)
                    {
                       outString[k] = outString[line_len-x+k];
                    }
                    i++;
                    break;

                }

                case RULE_OP_MANGLE_PREPEND:
                {
                    k = line_len-1;
                    while ( k !=-1)
                    {
                        outString[k+1] = outString[k];
                        k--;
                    }
                    outString[0]= ruleProp[0].RuleMap[ruleNum][i+1];
                    line_len ++;
                    i+=2;
                    break;
                }


                case RULE_OP_MANGLE_LREST:
                {
                    int b = 0;
                    for (b = 0; b<line_len; b++)
                    {
                        outString[b] = tolower(outString[b]);
                    }
                    i++;
                    break;
                }
                case RULE_OP_MANGLE_DUPECHAR_ALL:
                {
                    if ((line_len * 2 ) > BUFSIZ)
                        {
                            i++;
                            break;
                        }
                    memcpy(rule_temp,outString,line_len);
                    int b = 0;
                    int count = 0;
                    for (b = 0; b<line_len*2; b+=2)
                    {
                        outString[b] = rule_temp[count];
                        outString[b+1] = rule_temp[count];
                        count ++;
                    }
                    line_len = line_len *2;
                    i++;
                    break;
                }
                case RULE_OP_MANGLE_UREST:
                {
                    int b = 0;
                    for (b = 0; b<line_len; b++)
                    {
                        if (outString[b] > '`' && outString[b] < '{')
                        {
                            outString[b] = outString[b] -0x20;
                        }
                    }
                    i++;
                    break;
                }
                case RULE_OP_TITLE:
                {
                    int b = 0;
                    outString[0] = toupper(
                                           outString[0]);
                    for (b = 1; b<line_len; b++)
                    {
                        if (outString[b-1]== 32)
                        {
                            outString[b] = toupper(outString[b]);
                        }
                        else
                        {
                            outString[b] = tolower(outString[b]);
                        }
                    }
                    i++;
                    break;
                }
                case RULE_OP_MANGLE_LREST_UFIRST:
                {
                    int b = 0;
                    if (outString[0] > '`' && outString[0] < '{')
                    {
                        outString[0] = outString[0] -0x20;
                    }

                    for (b = 1; b<line_len; b++)
                    {
                        if (outString[b] > '@' && outString[b] < '[')
                        {
                            outString[b] = outString[b] +0x20;
                        }
                    }
                    i++;
                    break;
                }
                case RULE_OP_MANGLE_UREST_LFIRST:
                {
                    int b = 0;
                    if (outString[0] > '@' && outString[0] < '[')
                    {
                        outString[0] = outString[0] +0x20;
                    }

                    for (b = 1; b<line_len; b++)
                    {
                        if (outString[b] > '`' && outString[b] < '{')
                        {
                            outString[b] = outString[b] -0x20;
                        }
                    }
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_DELETE_LAST:
                {
                    k = 1;
                    while (ruleProp[0].RuleMap[ruleNum][i+1] == RULE_OP_MANGLE_DELETE_LAST)
                    {
                        k++; i++;
                    }

                    if (k>= line_len)
                    {
                        line_len = 0;
                        break;
                    }

                    line_len -=k;
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_DELETE_FIRST:
                {

                    k = 1;
                    while (ruleProp[0].RuleMap[ruleNum][i+1] == RULE_OP_MANGLE_DELETE_FIRST )
                    {
                        k++; i++;
                    }

                    if (k>=line_len)
                    {
                        line_len = 0;
                        break;
                    }

                    for (x =k; x<line_len;x++)
                    {
                        outString[x-k] = outString[x];
                    }
                    line_len -= k;
                    i++;
                    break;

                }
                case RULE_OP_MANGLE_REFLECT:
                {
                    int b = 0;
                    int c = line_len;
                    if ((line_len *2 ) > BUFSIZ)
                        {
                            i++;
                            break;
                        }
                    for (b = (line_len-1); b>=0; b--)
                    {
                        outString[c]= outString[b];
                        c++;
                    }
                    line_len = line_len *2;
                    i++;
                    break;
                }

                case RULE_OP_MANGLE_INSERT:
                {
                    if (posMap[ruleProp[0].RuleMap[ruleNum][i+1]] >= line_len)

                        {  i+=3;
                            continue;}

                    k = posMap[ruleProp[0].RuleMap[ruleNum][i+1]]-1;
                    x = line_len-1;

                    while (x>=k)  //Optimized routine saves memmove and memcpy using 1x loop
                    {
                        outString[x+1] = outString[x];
                        x--;
                    }
                    outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]] ] = *(ruleProp[0].RuleMap[ruleNum]+i+2);
                    line_len++;
                    i+=3;
                    break;
                }
                case RULE_OP_MANGLE_OVERSTRIKE:
                {
                    if (posMap[ruleProp[0].RuleMap[ruleNum][i+1]] >= line_len)
                        {i+=3;continue;}
                    outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = *(ruleProp[0].RuleMap[ruleNum]+i+2);
                    i+=3;
                    break;
                }
                case RULE_OP_MANGLE_TRUNCATE_AT:
                {
                    if (line_len >= posMap[ruleProp[0].RuleMap[ruleNum][i+1]]+1)
                    {
                        line_len = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    }
                    i+=2;
                    break;

                }
                case RULE_OP_MANGLE_REVERSE:
                {
                    char *p1, *p2;
                    if (!outString || !*outString)
                        break;

                    for (p1 = outString, p2 = outString + line_len - 1; p2 > p1; ++p1, --p2) {
                        *p1 ^= *p2;
                        *p2 ^= *p1;
                        *p1 ^= *p2;
                    }
                    i++;
                    break;

                }
                case RULE_OP_MANGLE_DUPEWORD:
                {
                    if ((line_len * 2) > BUFSIZ)
                        {
                            i++;
                            break;
                        }
                    memcpy(outString+line_len,outString,line_len);
                    line_len = line_len * 2;
                    i++;
                    break;
                }
                case RULE_OP_MANGLE_DUPEWORD_TIMES:
                {
                    //skip = 1;
                    int dupes = 0;
                    unsigned long oline_len = line_len;

                    for (dupes = posMap[ruleProp[0].RuleMap[ruleNum][i+1]]; dupes != 0; dupes--)
                    {
                        if ((line_len + oline_len) > BUFSIZ)
                        {
                            break;
                        }

                        memcpy(outString+line_len,outString,line_len);
                        line_len += oline_len;
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_MANGLE_DELETE_AT:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        for (x = posMap[ruleProp[0].RuleMap[ruleNum][i+1]]+1; x<line_len; x++)
                        {
                            outString[x-1] = outString[x];
                        }

                        line_len --;
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_MANGLE_DUPECHAR_FIRST:
                {
                    int reps = posMap[ruleProp[0].RuleMap[ruleNum][i+1]] ;

                    for (k = line_len-1; k!=-1; k--)
                    {
                        outString[k+reps] = outString[k]; //Shift everything x position up
                    }
                    for (k = reps;k!=-1;k--)
                    {
                        outString[k] = outString[reps]; //Fill everything before first letter with first letter
                    }

                    line_len+=posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    i +=2;
                    break;
                }
                case RULE_OP_MANGLE_DUPECHAR_LAST:
                {
                    //skip = 1;
                    int reps = posMap[ruleProp[0].RuleMap[ruleNum][i+1]] ;
                    int b = 0;

                    for (b = 0; b<reps; b++)
                    {
                        outString[line_len+b] =outString[line_len-1];
                    }
                    line_len += reps;
                    i+=2;
                    break;
                }
                case RULE_OP_SWAPFRONT:
                {
                    if (line_len > 1)
                    {
                        rule_temp[0] = outString[1];
                        outString[1] = outString[0];
                        outString[0] = rule_temp[0];
                    }
                    i++;
                    break;
                }
                case RULE_OP_SWAPBACK:
                {
                    if (line_len >1)
                    {
                        rule_temp[0] = *(outString+(line_len-1));
                        outString[line_len-1] =outString[line_len-2];
                        outString[line_len-2] = rule_temp[0];
                    }
                    i++;
                    break;
                }
                case RULE_OP_SWAPCHARS:
                {
                    //skip =2;
                    int num1 = 0;
                    int num2 = 0;
                    num1 = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    num2 = posMap[ruleProp[0].RuleMap[ruleNum][i+2]];

                    if ((line_len > num1) && (line_len > num2))
                    {
                        rule_temp[0] = outString[num1];
                        outString[num1] = outString[num2];
                        outString[num2] = rule_temp[0];
                    }
                    i+=3;
                    break;
                }
                case RULE_OP_CLONEBACKWARD:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]-1];
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_CLONEFORWARD:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]]+1)
                    {
                        outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]+1];
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_ASCIIUP:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]]+1;
                    }
                    i +=2;
                    break;
                }
                case RULE_OP_ASCIIDOWN:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]]-1;
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_BITWISEL:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] << 1;
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_BITWISER:
                {
                    if (line_len > posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] = outString[posMap[ruleProp[0].RuleMap[ruleNum][i+1]]] >> 1;
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_CLONEBLOCKF:
                {
                    if (line_len >= posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        memmove(outString+posMap[ruleProp[0].RuleMap[ruleNum][i+1]],outString,line_len);
                        line_len += posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    }
                    i+=2;
                    break;
                }
                case RULE_OP_CLONEBLOCKR:
                {
                    if (line_len >=posMap[ruleProp[0].RuleMap[ruleNum][i+1]])
                    {
                        memcpy(outString+line_len,outString+(line_len-posMap[ruleProp[0].RuleMap[ruleNum][i+1]]),posMap[ruleProp[0].RuleMap[ruleNum][i+1]]);
                        line_len += posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                    }
                    i+=2;
                    break;
                }

                //Hashcat Gating rules
                case RULE_GATE_LESS: //Rejects if length is greater than N
                    {
                        unsigned int val = ruleProp[0].RuleMap[ruleNum][i+1] - '0';
                        if (line_len >= val)
                        {
                            skipRule = 1;
                        }
                        i+=2;
                        break;
                    }
                case RULE_GATE_GREATER: //Rejects if length is less than N
                    {
                        //skip = 1;
                        unsigned int val = ruleProp[0].RuleMap[ruleNum][i+1] - '0';
                        if (line_len <= val)
                        {
                            skipRule = 1;
                        }
                        i+=2;
                        break;
                    }
                case RULE_GATE_CONTAIN:
                    {
                        //skip = 1;
                        if (memchr(outString,ruleProp[0].RuleMap[ruleNum][i+1],line_len) != NULL) //Search for the char within outString
                        {
                            skipRule = 1;
                        }
                        i+=2;
                        break;
                    }
                case RULE_GATE_NOT_CONTAIN:
                    {
                        //skip = 1;
                        if (memchr(outString,ruleProp[0].RuleMap[ruleNum][i+1],line_len) == NULL) //Search for the char within outString
                        {
                            skipRule = 1;
                        }
                        i+=2;
                        break;
                    }
                case RULE_GATE_LASTCHAR:
                    {
                        //skip = 1;
                        if (outString[line_len-1] != ruleProp[0].RuleMap[ruleNum][i+1])
                        {
                            skipRule = 1;
                        }
                        i+=2;
                        break;
                    }
                case RULE_GATE_FIRSTCHAR:
                    {
                        //skip= 1;
                        if (outString[0] != ruleProp[0].RuleMap[ruleNum][i+1])
                        {
                            skipRule = 1;
                        }
                        i+=2;
                        break;
                    }

                case RULE_GATE_EQUALSCHAR_AT: //Rejects if char at pos X != N
                    {
                        //skip = 2;
                        int pos = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                        if (outString[pos] != ruleProp[0].RuleMap[ruleNum][i+2])
                        {
                            skipRule = 1;
                        }
                        i+=3;
                        break;
                    }
                case RULE_GATE_CONTAINS_NUM: //Rejects if char at pos X != N
                    {
                        //skip = 2;
                        int count = posMap[ruleProp[0].RuleMap[ruleNum][i+1]];
                        int instance = 0;

                        for (k = 0; k<line_len; k++)
                        {
                            if (outString[k] == ruleProp[0].RuleMap[ruleNum][i+2])
                            {
                                instance ++;
                                if (instance >= count)
                                {
                                    break;
                                }
                            }
                        }
                        if (instance < count)
                        {
                            skipRule = 1;
                        }

                        i+=3;
                        break;

                    }
                case RULE_GATE_MEM_CONTAINS:
                    {
                        //skip = 1;

                        if (memcmp(outString,rule_mem,line_len) == 0)
                        {
                            skipRule = 1;
                        }
                        i+=2;
                    }
                //End hashcat gating rules

                case RULE_MEM_TOGGLE:
                {


                    if (mem_mode == 0)
                    {
                        memcpy(line_toggle,outString,line_len);
                        memcpy(outString,rule_mem,mem_len);

                        long temp_len = line_len; //Carry the len variable across using a temp swap var
                        line_len = mem_len;
                        mem_len = temp_len;

                        mem_mode = 1;
                    }
                    else
                    {
                        memcpy(rule_mem, outString,line_len);
                        memcpy(outString,line_toggle,mem_len);

                        long temp_len = line_len; //Carry the len variable across using a temp swap var
                        line_len = mem_len;
                        mem_len = temp_len;

                        mem_mode = 0;
                    }
                    i++;
                    break;

                }
                 default:
                {
                    i++;
                    break;
                }
            }
        }

        if (skipRule == 0)
        {
            if (line_len != 0)
            {
                outString[line_len] = 0;
                return line_len;
            }
        }
        outString[0] = 0;
    }
    return 0;
}

