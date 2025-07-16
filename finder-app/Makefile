CROSS_COMPILER?=

default:
	echo $(shell pwd)
	$(CROSS_COMPILER)gcc writer.c -o writer
	file writer > ../assignment2/fileresult.txt

clean:
	rm -rf *.o ./writer


