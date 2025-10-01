from flask import Flask, request
import json
import mysql.connector

app = Flask(__name__)
hostSql = '127.0.0.1'
userSql = 'root'
passSql = '1919'
databaseSql = 'test'

@app.route('/')
def index():
    name = request.args.get('name', 'Anonymous')
    return f"Hi, {name}!"

@app.route('/check')
def check():
    if checkTableAll():
        return returnResponse('200', 'all table is exist')
    else:
        return returnResponse('204', 'all table is created')

@app.route('/save')
def save():
    idproject = request.args.get('idproject', '')
    isDoneStr = request.args.get('isdone', "false")
    isDone = isDoneStr=="true"
    idtask = request.args.get('idtask', '')
    taskinput = request.args.get('taskinput', '')
    conn = mysql.connector.connect(
        host=hostSql,
        user=userSql,
        password=passSql,
        database=databaseSql
    )
    cursor = conn.cursor()
    print("get is done "+str(type(isDone)))
    if isDone :
        cursor.execute(f"DELETE FROM `workresume` WHERE `idproject` = '{idproject}' and `idtask` = '{idtask}'")
        conn.commit()
        return returnResponse('200', 'task is marked as done')
    else:
        cursor.execute(f"UPDATE `workresume` SET `taskdesc`='{taskinput}', `isprogress`= false WHERE `idproject` = '{idproject}' and `idtask` = '{idtask}'")
        conn.commit()
        return returnResponse('200', 'status task is updated')
@app.route('/getworkrunning')
def getworkrunning():
    idproject = request.args.get('idproject', '')
    idtask = request.args.get('idtask', '')
    conn = mysql.connector.connect(
        host=hostSql,
        user=userSql,
        password='',
        database=databaseSql
    )
    returnStr = ""
    cursor = conn.cursor(buffered=True)
    cursor.execute(f"SELECT `idtask` from `workresume` WHERE `idproject` = '{idproject}' and `isprogress`= false")
    rows = cursor.fetchall()
    for row in rows:
        returnStr += "\""+row[0]+"\","
    return "{\"list\": ["+returnStr[:-1]+"]}"

@app.route('/resume')
def resume():
    idproject = request.args.get('idproject', '')
    idtask = request.args.get('idtask', '')
    conn = mysql.connector.connect(
        host=hostSql,
        user=userSql,
        password=passSql,
        database=databaseSql
    )
    # todo: add column that mark row as in progress
    cursor = conn.cursor(buffered=True)
    if idtask == "":
        cursor.execute(f"SELECT `idtask` from `workresume` WHERE `idproject` = '{idproject}' and `isprogress`= false")
        getId = cursor.fetchone()
        if getId is None :
            return returnResponse('205', 'data is failed process')
        else:
            idtask = getId[0]
    # check resume?
    cursor.execute(f"SELECT `idproject`, `idtask`, `taskdesc`, `isprogress` FROM `workresume` WHERE `idproject` = '{idproject}' and `idtask` = '{idtask}'")
    result = cursor.fetchone()
    if result is not None :
        isprogress = result[3]
        if isprogress :
            return returnResponse('205', 'task is running')
        cursor.execute(f"UPDATE `workresume` SET `isprogress`= 1 WHERE `idproject` = '{idproject}' and `idtask` = '{idtask}'")
        conn.commit()
        response = {
            "responseCode": "200",
            "idproject": result[0],
            "idtask": result[1],
            "taskdesc": result[2]
        }
        return json.dumps(response)
    else:
        return returnResponse('205', 'task is not found')
@app.route('/newtask')
def newtask():
    conn = mysql.connector.connect(
        host=hostSql,
        user=userSql,
        password=passSql,
        database=databaseSql
    )
    cursor = conn.cursor()
    idproject = request.args.get('idproject', '')
    cursor.execute(f"SELECT lastid FROM `tasklastid` WHERE `idproject` like '{idproject}'")
    result = cursor.fetchone()
    if result is None:
        lastidtask = format(1, 'x')
        # cursor.execute(f"INSERT INTO `tasklastid`(`idproject`, `lastid`) VALUES ('{}', '{lastidtask}')")
    else:
        lastidtask = result[0]    
    nextlastidtask = format(int(lastidtask, 16)+1, 'x')
    print(f"get id: {nextlastidtask}")
    req = request.args.get('req', '') # example: 192.169.12.1-192.169.12.200
    if(idproject=="shodanscan"):
        cursor.execute(f"INSERT INTO `workresume`(`idproject`, `idtask`, `taskdesc`) VALUES ('{idproject}','{nextlastidtask}','{req}')")
        cursor.execute(f"UPDATE `tasklastid` SET `lastid`='{nextlastidtask}' WHERE `idproject` = '{idproject}'")
        conn.commit()
        return returnResponse('200', 'new task is success created')
    else:
        cursor.execute(f"INSERT INTO `workresume`(`idproject`, `idtask`, `taskdesc`) VALUES ('{idproject}','{nextlastidtask}','{req}')")
        cursor.execute(f"UPDATE `tasklastid` SET `lastid`='{nextlastidtask}' WHERE `idproject` = '{idproject}'")
        conn.commit()
        return returnResponse('200', 'new task is success created')
def checkTableAll():
    conn = mysql.connector.connect(
        host=hostSql,
        user=userSql,
        password=passSql,
        database=databaseSql
    )
    cursor = conn.cursor()
    if checkTable(cursor, "workresume")==False:
        cursor.execute("""
        CREATE TABLE `workresume` (
            `id` int(20) NOT NULL,
            `idproject` varchar(200) NOT NULL,
            `idtask` varchar(200) NOT NULL,
            `taskdesc` varchar(300) NOT NULL,
            `isprogress` tinyint(1) NOT NULL DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
        ALTER TABLE `workresume`
            ADD PRIMARY KEY (`id`);
        ALTER TABLE `workresume`
            MODIFY `id` int(20) NOT NULL AUTO_INCREMENT;
        """)
        return False
    if checkTable(cursor, "tasklastid")==False:
        cursor.execute("""
        CREATE TABLE `tasklastid` (
            `id` int(20) NOT NULL,
            `idproject` varchar(200) NOT NULL,
            `lastid` varchar(200) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=latin1;
        ALTER TABLE `tasklastid`
            ADD PRIMARY KEY (`id`);
        ALTER TABLE `tasklastid`
            MODIFY `id` int(20) NOT NULL AUTO_INCREMENT;
        """)
        return False
    return True

def returnResponse(errorCode, desc):
    return "{\"responseCode\": "+errorCode+", \"desc\": \""+desc+"\"}"
def checkTable(cursor, table_name):
    cursor.execute("SHOW TABLES LIKE %s;", (table_name,))
    result = cursor.fetchone()
    return result is not None
# table workresume (id, idproject, idtask, taskdesc)
# table tasklastid (id, idproject, lastid)
# endpoint: /resume (idproject, idtask) response: (taskinput)
# endpoint: /save (idproject, idtask, taskinput) response: (statuscode)
# endpoint: /newtask (idproject, req) response: (statuscode)

if __name__ == '__main__':
    app.run(debug=True)
