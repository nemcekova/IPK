typedef struct telem{
    int port_num;
    struct telem *nextPtr;
}TElem;

typedef struct tlist{
    TElem *first;
    TElem *act;
}TList;