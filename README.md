# pyew-2.0-linux
comment-sync

用于同步服务端的注释信息,注释相关代码在pyew_core.py 202 - 220行 , 大家可按需添加代码.

Tasks \n

 label功能: 实现添加注释 \n
 服务器端同步：使用submit.py 上传和同步注释 \n
 注释同步冲突检测（ 同时添加／更新， 死锁 ）\n
 多线程，定时访问服务器检测数据更新\n