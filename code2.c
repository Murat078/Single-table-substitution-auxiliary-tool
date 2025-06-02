#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

#define ALPHABET_SIZE 26
#define MAX_TEXT_LENGTH 1000
#define MAX_WORD_LENGTH 50

// 标准英语字母频率 按A-Z顺序
const float english_freq[ALPHABET_SIZE] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 
    0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 
    6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074
};

// 常见短词列表
const char *common_words[] = {
   
    "AM", "AN", "AS", "AT", "BY", "DO", "GO", "HE", "IF", "IN", 
    "IS", "IT", "ME", "MY", "NO", "OF", "ON", "OR", "SO", "TO", 
    "UP", "US", "WE",
  
    "AGO", "ALL", "AND", "ANY", "BUT", "CAN", "DAY", "END", "HAD", "HER", 
    "HIS", "HOW", "LET", "MAY", "NOT", "NOW", "ONE", "OUR", "OUT", "OWN", 
    "SHE", "WAS", "YOU",
    
    "ALSO", "AWAY", "BEST", "DEAR", "DOWN", "EVEN", "EVER", "HAVE", "JUST", "MANY", 
    "MOST", "MUCH", "NEED", "NEXT", "NONE", "ONCE", "ONLY", "OVER", "PAST", "SAME", 
    "SUCH", "THIS", "THAN", "THEN", "THAT", "UPON", "WHAT", "VERY", "WISH", "YOUR",
  
    "ABOUT", "ABOVE", "AFTER", "AGAIN", "AHEAD", "ALONG", "COULD", "LEAST", "LATER", "OFTEN", 
    "OTHER", "SHALL", "SINCE", "THERE", "WHERE", "WHICH", "UNDER", "UNTIL", "WOULD",
  
    "ACROSS", "BEFORE", "BEHIND", "BELONG", "BESIDE", "DOUBLE", "DURING", "ENOUGH", "EXCEPT", "HARDLY", 
    "MERELY", "RATHER", "REALLY", "SELDOM", "THOUGH", "UNLESS",
   
    "BECAUSE",
    NULL
};

typedef struct {
    char substitution[ALPHABET_SIZE];  // 替换表 (A-Z的映射)
    char reverse_sub[ALPHABET_SIZE];   // 反向替换表
    int known_positions;               // 已知的替换数量
} CipherKey;

typedef struct {
    int count;
    float frequency;
} LetterStats;

typedef struct {
    char cipher_char;
    char plain_char;
    float score;
} Suggestion;


void initializeKey(CipherKey *key);
void encrypt(const char *plaintext, char *ciphertext, CipherKey *key);
void decrypt(const char *ciphertext, char *plaintext, CipherKey *key);
void generateRandomKey(CipherKey *key);
void analyzeFrequency(const char *text, LetterStats stats[]);
void printFrequencyAnalysis(LetterStats stats[]);
void suggestMappings(LetterStats cipher_stats[], Suggestion suggestions[]);
void printSuggestions(Suggestion suggestions[]);
void applySuggestion(CipherKey *key, char cipher_char, char plain_char);
void partialDecrypt(const char *ciphertext, char *partial, CipherKey *key);
int findPossibleWords(const char *partial, CipherKey *key);
void interactiveCrack(const char *ciphertext);


int main() {
    srand(time(0)); // 初始化随机数种子
    char plaintext[MAX_TEXT_LENGTH] = {0};
    char ciphertext[MAX_TEXT_LENGTH] = {0};
    char decrypted[MAX_TEXT_LENGTH] = {0};
    CipherKey key;

    const char ppt_sample[] = "hzsrnqc klyy wqc flo mflwf ol zqdn nsoznj wskn lj xzsrbjnf,wzsxz gqv zqhhnf ol ozn glco zlfnco hnlhrn;nsoznj jnrqosdnc lj fnqj kjsnfbc,wzsxz sc xnjoqsfrv gljn efeceqr.zn rsdnb qrlfn sf zsc zlecn sf cqdsrrn jlw,wzsoznj flfn hnfnojqonb.q csfyrn blgncosx cekksxnb ol cnjdn zsg.zn pjnqmkqconb qfb bsfnb qo ozn xrep,qo zlejc gqozngqosxqrrv ksanb,sf ozn cqgn jllg,qo ozn cqgn oqprn,fndnj oqmsfy zsc gnqrc wsoz loznj gngpnjc,gexz rncc pjsfysfy q yenco wsoz zsg;qfb wnfo zlgn qo naqxorv gsbfsyzo,lfrv ol jnosjn qo lfxn ol pnb.zn fndnj ecnb ozn xlcv xzqgpnjc wzsxz ozn jnkljg hjldsbnc klj soc kqdlejnb gngpnjc.zn hqccnb onf zlejc leo lk ozn ownfov-klejsf cqdsrrn jlw,nsoznj sf crnnhsfy lj gqmsfy zsc olsrno.";
    
    initializeKey(&key);
    
    int choice;
    do {
        printf("\n=== 单表代换密码工具 ===\n");
        printf("1. 加密\n");
        printf("2. 解密\n");
        printf("3. 生成随机密钥\n");
        printf("4. 破译密文\n");
        printf("5.对PPT样例进行单表代换破解\n");
        printf("0. 退出\n");
        printf("选择: ");
        scanf("%d", &choice);
        getchar(); // 消耗换行符
        
        switch(choice) {
            case 1:
                printf("输入明文: ");
                fgets(plaintext, MAX_TEXT_LENGTH, stdin);
                plaintext[strcspn(plaintext, "\n")] = 0; // 移除换行符
                encrypt(plaintext, ciphertext, &key);
                printf("密文: %s\n", ciphertext);
                break;
            case 2:
                printf("输入密文: ");
                fgets(ciphertext, MAX_TEXT_LENGTH, stdin);
                ciphertext[strcspn(ciphertext, "\n")] = 0;
                decrypt(ciphertext, decrypted, &key);
                printf("明文: %s\n", decrypted);
                break;
            case 3:
                generateRandomKey(&key);
                printf("新密钥已生成。\n");
                break;
            case 4:
                printf("输入要破译的密文: ");
                fgets(ciphertext, MAX_TEXT_LENGTH, stdin);
                ciphertext[strcspn(ciphertext, "\n")] = 0;
                interactiveCrack(ciphertext);
                break;
            case 5:
                printf("\n对PPT样例进行单表代换破解\n");
                printf("样例密文:\n%s\n", ppt_sample);
                interactiveCrack(ppt_sample);
                break;
            case 0:
                printf("退出程序。\n");
                break;
            default:
                printf("无效选择。\n");
        }
    } while(choice != 0);
    
    return 0;
}

// 初始化密钥
void initializeKey(CipherKey *key) {
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        key->substitution[i] = '?';
        key->reverse_sub[i] = '?';
    }
    key->known_positions = 0;
}

// 加密函数
void encrypt(const char *plaintext, char *ciphertext, CipherKey *key) {
    int len = strlen(plaintext);
    for(int i = 0; i < len; i++) {
        char c = toupper(plaintext[i]);
        if(isalpha(c)) {
            int index = c - 'A';
            if(key->substitution[index] != '?') {
                ciphertext[i] = key->substitution[index];
            } else {
                ciphertext[i] = c; // 未定义替换，保持原样
            }
        } else {
            ciphertext[i] = c; // 非字母字符保持不变
        }
    }
    ciphertext[len] = '\0';
}

// 解密函数
void decrypt(const char *ciphertext, char *plaintext, CipherKey *key) {
    int len = strlen(ciphertext);
    for(int i = 0; i < len; i++) {
        char c = toupper(ciphertext[i]);
        if(isalpha(c)) {
            int index = c - 'A';
            if(key->reverse_sub[index] != '?') {
                plaintext[i] = key->reverse_sub[index];
            } else {
                plaintext[i] = c; // 未定义替换，保持原样
            }
        } else {
            plaintext[i] = c; // 非字母字符保持不变
        }
    }
    plaintext[len] = '\0';
}

// 生成随机密钥
void generateRandomKey(CipherKey *key) {
    char remaining[ALPHABET_SIZE];
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        remaining[i] = 'A' + i;
    }
    
    // Fisher-Yates 洗牌算法
    for(int i = ALPHABET_SIZE - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char temp = remaining[i];
        remaining[i] = remaining[j];
        remaining[j] = temp;
    }
    
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        key->substitution[i] = remaining[i];
        key->reverse_sub[remaining[i] - 'A'] = 'A' + i;
    }
    key->known_positions = ALPHABET_SIZE;
}

// 分析字母频率
void analyzeFrequency(const char *text, LetterStats stats[]) {
    int total_letters = 0;
    
    // 初始化统计
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        stats[i].count = 0;
        stats[i].frequency = 0.0;
    }
    
    // 统计字母出现次数
    int len = strlen(text);
    for(int i = 0; i < len; i++) {
        char c = toupper(text[i]);
        if(isalpha(c)) {
            stats[c - 'A'].count++;
            total_letters++;
        }
    }
    
    // 计算频率
    if(total_letters > 0) {
        for(int i = 0; i < ALPHABET_SIZE; i++) {
            stats[i].frequency = (stats[i].count * 100.0) / total_letters;
        }
    }
}

// 打印频率分析
void printFrequencyAnalysis(LetterStats stats[]) {
    printf("\n字母频率分析:\n");
    printf("字母\t计数\t频率\t英语频率\n");
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        printf("%c\t%d\t%.2f%%\t%.2f%%\n", 
               'A' + i, stats[i].count, stats[i].frequency, english_freq[i]);
    }
}

// 生成替换建议
void suggestMappings(LetterStats cipher_stats[], Suggestion suggestions[]) {
    // 对密文字母按频率排序
    int indices[ALPHABET_SIZE];
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        indices[i] = i;
    }
    
    // 对频率简单冒泡排序 
    for(int i = 0; i < ALPHABET_SIZE - 1; i++) {
        for(int j = 0; j < ALPHABET_SIZE - i - 1; j++) {
            if(cipher_stats[indices[j]].frequency < cipher_stats[indices[j+1]].frequency) {
                int temp = indices[j];
                indices[j] = indices[j+1];
                indices[j+1] = temp;
            }
        }
    }
    
    // 对标准英语字母频率排序
    int english_indices[ALPHABET_SIZE];
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        english_indices[i] = i;
    }
    
    for(int i = 0; i < ALPHABET_SIZE - 1; i++) {
        for(int j = 0; j < ALPHABET_SIZE - i - 1; j++) {
            if(english_freq[english_indices[j]] < english_freq[english_indices[j+1]]) {
                int temp = english_indices[j];
                english_indices[j] = english_indices[j+1];
                english_indices[j+1] = temp;
            }
        }
    }
    
    // 建议
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        suggestions[i].cipher_char = 'A' + indices[i];
        suggestions[i].plain_char = 'A' + english_indices[i];
        suggestions[i].score = fabs(cipher_stats[indices[i]].frequency - english_freq[english_indices[i]]);
    }
}

// 打印替换建议
void printSuggestions(Suggestion suggestions[]) {
    printf("\n替换建议 (密文字母 -> 明文字母):\n");
    for(int i = 0; i < ALPHABET_SIZE; i++) {
        printf("%c -> %c (差异: %.2f%%)\n", 
               suggestions[i].cipher_char, suggestions[i].plain_char, suggestions[i].score);
    }
}

// 应用替换建议
void applySuggestion(CipherKey *key, char cipher_char, char plain_char) {
    cipher_char = toupper(cipher_char);
    plain_char = toupper(plain_char);
    
    // 检查有没有已经定义过
    if(key->reverse_sub[cipher_char - 'A'] != '?') {
        printf("警告: %c 已经被映射到 %c\n", cipher_char, key->reverse_sub[cipher_char - 'A']);
        return;
    }
    
    if(key->substitution[plain_char - 'A'] != '?') {
        printf("警告: %c 已经映射到密文字母 %c\n", plain_char, key->substitution[plain_char - 'A']);
        return;
    }
    
    // 替换
    key->substitution[plain_char - 'A'] = cipher_char;
    key->reverse_sub[cipher_char - 'A'] = plain_char;
    key->known_positions++;
    
    printf("已应用替换: %c -> %c\n", cipher_char, plain_char);
}

// 部分解密
void partialDecrypt(const char *ciphertext, char *partial, CipherKey *key) {
    int len = strlen(ciphertext);
    for(int i = 0; i < len; i++) {
        char c = toupper(ciphertext[i]);
        if(isalpha(c)) {
            if(key->reverse_sub[c - 'A'] != '?') {
                partial[i] = tolower(key->reverse_sub[c - 'A']); // 用小写表示已知解密
            } else {
                partial[i] = c; // 大写表示尚未解密
            }
        } else {
            partial[i] = c; // 非字母字符
        }
    }
    partial[len] = '\0';
}

// 查找可能的单词
int findPossibleWords(const char *partial, CipherKey *key) {
    printf("\n可能的单词匹配:\n");
    int found = 0;
    
    // 分割部分解密文本为单词
    char temp[MAX_TEXT_LENGTH];
    strcpy(temp, partial);
    char *token = strtok(temp, " ");
    
    while(token != NULL) {
        int len = strlen(token);
        if(len >= 2 && len <= 7) { // 现在检查2-7字母的词
            // 检查是否有足够多的已解密字母
            int known_letters = 0;
            for(int i = 0; i < len; i++) {
                if(islower(token[i])) known_letters++;
            }
            
            if(known_letters >= 1) { // 至少有一个已知字母
                // 构建模式 (例如 "T_E" -> "T?E")
                char pattern[MAX_WORD_LENGTH] = {0};
                for(int i = 0; i < len; i++) {
                    if(islower(token[i])) {
                        pattern[i] = toupper(token[i]);
                    } else if(isupper(token[i])) {
                        pattern[i] = '?';
                    } else {
                        pattern[i] = token[i];
                    }
                }
                
                // 在常见词中查找匹配
                for(int i = 0; common_words[i] != NULL; i++) {
                    if(strlen(common_words[i]) == len) {
                        int match = 1;
                        for(int j = 0; j < len; j++) {
                            if(pattern[j] != '?' && pattern[j] != common_words[i][j]) {
                                match = 0;
                                break;
                            }
                        }
                        
                        if(match) {
                            printf("'%s' 可能匹配 '%s'\n", token, common_words[i]);
                            found = 1;
                            
                            // 建议新的映射
                            for(int j = 0; j < len; j++) {
                                if(pattern[j] == '?') {
                                    printf("建议: %c -> %c\n", token[j], common_words[i][j]);
                                }
                            }
                        }
                    }
                }
            }
        }
        token = strtok(NULL, " ");
    }
    
    if(!found) {
        printf("未找到明显的单词匹配。尝试分析字母频率。\n");
    }
    
    return found;
}

// 交互式破译
void interactiveCrack(const char *ciphertext) {
    CipherKey key;
    initializeKey(&key);
    
    char partial[MAX_TEXT_LENGTH];
    LetterStats stats[ALPHABET_SIZE];
    Suggestion suggestions[ALPHABET_SIZE];
    
    int step = 1;
    while(key.known_positions < ALPHABET_SIZE) {
        printf("\n=== 破译步骤 %d ===\n", step++);
        printf("当前已知替换: %d/26\n", key.known_positions);
        
        // 分析频率
        analyzeFrequency(ciphertext, stats);
        printFrequencyAnalysis(stats);
        
        // 生成建议
        suggestMappings(stats, suggestions);
        printSuggestions(suggestions);
        
        // 显示部分解密结果
        partialDecrypt(ciphertext, partial, &key);
        printf("\n部分解密结果:\n%s\n", partial);
        
        // 尝试匹配单词
        findPossibleWords(partial, &key);
        
        // 用户交互
        printf("\n选择操作:\n");
        printf("1. 应用替换建议\n");
        printf("2. 手动输入替换\n");
        printf("3. 显示当前密钥\n");
        printf("4. 完成破译\n");
        printf("选择: ");
        
        int choice;
        scanf("%d", &choice);
        getchar(); // 消耗换行符
        
        switch(choice) {
            case 1: {
                printf("输入要应用的建议编号 (0-%d): ", ALPHABET_SIZE-1);
                int suggestion_num;
                scanf("%d", &suggestion_num);
                getchar();
                
                if(suggestion_num >= 0 && suggestion_num < ALPHABET_SIZE) {
                    applySuggestion(&key, suggestions[suggestion_num].cipher_char, 
                                   suggestions[suggestion_num].plain_char);
                } else {
                    printf("无效编号。\n");
                }
                break;
            }
            case 2: {
                char cipher_char, plain_char;
                printf("输入密文字母: ");
                scanf("%c", &cipher_char);
                getchar();
                printf("输入对应的明文字母: ");
                scanf("%c", &plain_char);
                getchar();
                
                if(isalpha(cipher_char) && isalpha(plain_char)) {
                    applySuggestion(&key, cipher_char, plain_char);
                } else {
                    printf("无效字母。\n");
                }
                break;
            }
            case 3: {
                printf("\n当前替换表:\n");
                for(int i = 0; i < ALPHABET_SIZE; i++) {
                    printf("%c -> %c\n", 'A' + i, 
                           key.substitution[i] != '?' ? key.substitution[i] : '?');
                }
                break;
            }
            case 4: {
                printf("破译完成。\n");
                return;
            }
            default:
                printf("无效选择。\n");
        }
    }
    
    printf("\n破译完成! 所有字母替换已确定。\n");
    printf("最终解密结果:\n");
    char final[MAX_TEXT_LENGTH];
    decrypt(ciphertext, final, &key);
    printf("%s\n", final);
}


