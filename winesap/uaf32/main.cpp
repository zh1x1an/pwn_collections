#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
using namespace std;

class A{
	public:
		virtual void print(){
			puts("class A");
		}
};

class B: public A{
	public:
		void print(){
			puts("class B");
		}
};

void backdoor()
{
	system("/bin/sh");
}

char buf[1024];

int main(int argc, char const *argv[])
{
	setvbuf(stdout,0,_IONBF,0);
	setvbuf(stdin,0,_IONBF,0);

	A *p = new B();
	delete p;

	fgets(buf,sizeof(buf),stdin);
	char *q = strdup(buf);

	p->print();
	return 0;
}
