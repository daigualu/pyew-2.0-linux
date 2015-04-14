import os,sqlite3
from time import time

DATABASE_PATH = os.path.abspath(os.path.join(os.path.dirname("__file__"),os.path.pardir)) + os.sep + "files.sqlite"

def createTableSig(db):
    try:
        sql = """create table if not exists signature (id time primary key, sig varchar)"""
        db.execute(sql)
    except:
        print 'create table signature failed..'



def insertTable(db,atime,hexContent):
    try:
        sql = """insert into signature (id,sig) values (?, ?)"""
        db.execute(sql, (atime, hexContent))
        db.commit()
        print 'enter data into database successfully..'
    except:
        print 'insert table failed..'



def extractSig(pyew,doprint=True):
    cmd = raw_input('sOffset eOffset:')
    sOffset = -1
    eOffset = -1
    try:
        data = cmd.split(" ")
        if len(data) == 2:
            if data[0].isdigit():
                sOffset = int(data[0])
            elif data[0][:2].lower() == "0x":
                sOffset = int(data[0],16)
            else:
                print 'input the data was wrong..'
                return
            if data[1].isdigit():
                eOffset = int(data[1])
            elif data[1][:2].lower() == "0x":
                eOffset = int(data[1],16)
            else:
                print 'input the data was wrong..'
                return
        hexContent = ''
        buf = pyew.getBuffer()[sOffset:eOffset]
        for c in ["%02X" % ord(x) for x in buf]:
            hexContent += c
        print hexContent
        db = sqlite3.connect(DATABASE_PATH)
        cur = db.cursor()
        #createTableSig(db)  #create table..
        #cur.execute("drop table signature")  #delete table..
        atime = time()
        insertTable(db,atime,hexContent)
        #print cur.execute("select * from signature").fetchall()
        db.close()
    except:
        print "Error"
    
functions = {"exsig":extractSig}
