hook_shmXXX
===========
== author               
Oyayubi11                                                                   

== about 
LD_PRELOADを利用して、shmget/shmat/shmdt/shmctl()の情報をlogへ記録するプログラム。    
Ubuntuにて動作確認。   
 
== ベースファイル        
http://www.t-dori.net/forensics/hook_tcp.cpp

== compile         
付属のMakefile参照のこと

== how to use     
通常のプログラムを実行する際に、環境変数でLD_PRELOAD=./libhookShm.soを指定する。

libhookShm.soはshmXXX関数を使用するプログラムであれば、どのようなプログラムでも使用できる。

ただし、そのまま置き換えただけでは、元の関数が呼び出されなくなってしまうため、
 [関数呼び出し元] -> [置き換えた関数] -> [オリジナルの関数]
という感じで、soで置き換えた関数の中からオリジナルの関数を呼ぶようにして、
置き換えた関数の中で、ログを出力するようにしている。

== 注意点
sbit付与+root権限バイナリにはLD_PRELOADが適用されないため、
コンパイル時にライブラリを組み込むこと。
