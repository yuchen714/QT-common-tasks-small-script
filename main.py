import time
import requests
import paramiko   
import logging
import sys
import os
import socket
import pandas as pd
import json
import re
import datetime
import http.client
import hashlib

def SSHLinux(ip,port,username,password,bash):       #程序SSH连接函数，Linux批量管理功能的核心方法
	"""
	Linux批量管理功主方法
	input：ip，端口，用户名，ssh密码，执行的命令
	output： 执行结果（无法创建ssh连接则返回0,命令执行超时则返回2)
	"""
	a = 'client'
	b = 'stdin'
	c = 'stdout'
	d = 'stderr'
	client = paramiko.SSHClient()   #创建连接对象
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy)  #添加num个主机名及主机密钥到本地HostKeys对象
	try:
		client.connect(hostname=ip,port=port,username=username,password=password) #连接
		logging.info(f'主机{ip}连接成功！')
	except:
		logging.error(f'主机{ip}连接失败，请确认输入信息！')
		return(0)
	try:
		b,c,d= client.exec_command(bash,timeout=190)      #执行bash命令
		stdout=c.read().decode('utf-8')		#正确输出
		stderr=d.read().decode('utf-8')		#错误输出
		
		logging.info(f'----------------------{ip}信息----------------------')
		logging.info(stdout+stderr)
		logging.info(f'----------------------{ip}信息end----------------------')
		
		return(stdout+stderr)         #打印正确输出
		# ~ client.close()
	except:
		print("命令执行超时")
		return(2)
		
def CSVRead(filename):
	"""
	读取CSV文件
	input：CSV文件名
	output： 对应的DataFrame（读取失败则返回0）
	"""
	try:
		file = pd.read_csv(filename)
		df = pd.DataFrame(file)
		return(df)
	except:
		try:
			file = pd.read_csv(filename, encoding = "gbk")
			df = pd.DataFrame(file)
			return(df)
		except:
			logging.error(f'ip列表读取失败，请确认文件是否存在！')
			print(f'ip列表读取失败，请确认文件是否存在！')
			return(0)



def CSVWrite(filepath,filename,data):
	"""
	输出至CSV文件
	input：存储路径,CSV文件名,对应的DataFrame
	output： 1（失败则返回0）
	"""
	try:		#创建路径
		filepath=filepath.rstrip("\\")
		isExists=os.path.exists(filepath)
		if not isExists:
			os.makedirs(filepath)
		logging.info(f'{filepath}路径创建成功')
	except:
		logging.error(f'创建{filepath}路径失败')
		return(0)
		
	try:		#输出数据至CSV
		data.to_csv(filepath+'/'+filename,encoding='utf_8_sig')
		logging.info(f'输出结果至CSV文件{filepath}/{filename}')
		return(1)
	except:
		logging.error(f'输出结果至CSV文件失败')
		return(0)
		

def check_agent_status(ip,port,username,password):
	"""
	判断agent状态
	input：ip，端口，用户名，ssh密码，
	output：agent状态: 1良好 0可能异常 2进程不存在
	"""
	search1=SSHLinux(ip,port,username,password,"ps -ef |grep 'titanagent -d'|grep -v grep")
	search2=SSHLinux(ip,port,username,password,"tail -n 50000 /var/log/titanagent/sys.log |grep 'send heart beat msg'")
	# ~ print("search1="+search1)
	# ~ print("search2="+search2)
	if ("/etc/titanagent" in search1):	#判断进程是否存在
		if ("INFO" in search2):
			return(1)
		else:
			return(0)
	else:
		return(2)


def check_link_status(host, port):
	"""
	判断网络状态
	input：IP,ssh端口
	output：网络状态
	"""
	sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sk.settimeout(2)
	try:
		sk.connect((host,port))
		return "良好"
	except Exception:
		return "不可达"
		sk.close()

def check_reason_for_installation_failure(txt):
	"""
	判断agent安装失败原因
	input：install.log
	output：失败原因
	"""
	check1="failed to download intall_agent.sh"
	check2="error while loading shared libraries"
	if(check1 in txt):
		return("安装失败,这台主机疑似无法和服务端通信,请检查网络策略")
	elif(check2 in txt):
		return("安装失败,这台主机的操作系统了疑似在产品边界之外，请确认这台主机的操作系统")
	else:
		return("安装失败,这台主机疑似无法和服务端通信,请检查网络策略")
	

	
def get_all_group(ip,cookie,osType):
	"""
	获取数据，通过爬虫获取所有业务组
	input： ip, SESSION_ID cookie, 操作系统（win/linux）
	output： json
	"""
	url =f'http://{ip}/v1/assets/permission/agentgroup/self/grouplist' 
	
	headers = {
	"Content-Type": "application/json;charset=UTF-8",
	"Origin": f"http://{ip}",
	"Referer": f"http://{ip}/v3/",
    "Cookie": f"SESSION_ID={cookie}" , #改这里
    }
    
	if("win" in osType):
		osType = 2
	elif("inux" in osType):
		osType = 1
    
	post_param = json.dumps({"params":{"osType":osType}})

	# ~ proxy={'http':'http://192.168.194.142:8081'}
	# ~ html = requests.post(url=url, data=post_param, headers=headers,proxies=proxy).text
	html = requests.post(url=url, data=post_param, headers=headers).json()
	return(html)

def group_to_DF(html,bash):
	"""
	处理数据，处理包含业务组信息的json,转换为DataFrame格式
	input： json
	output： DataFrame
	"""
	list2 = [] #这个list存储所有二级业务组的groupId
	
	for item in html['rows']: 
		if (item['parentId'] == 0):#如果是一层业务组
			i = 1 #确保循环正常运行，无含义
		else:#如果不是一层业务组
			for item2 in html['rows']: 
				if (item2['groupId'] == item['parentId']):
					if (item2['parentId'] == 0):#如果是二层业务组
						list2.append(str(item['groupId']))#向list存储二级业务组的groupId			
	
	df = pd.DataFrame(columns=['1级业务组','2级业务组','3级业务组','4级业务组','agent安装命令'])
	for item in html['rows']:  
		# ~ print(item)
		if (item['parentId'] == 0):#如果是一层业务组
			line={'1级业务组':item['name'],'agent安装命令':re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash)}
			df = df.append(line,ignore_index=True)
		else:#如果不是一层业务组
			for item2 in html['rows']: 
				if (item2['groupId'] == item['parentId']):
					if (item2['parentId'] == 0):#如果是二层业务组
						line={'1级业务组':item2['name'],'2级业务组':item['name'],'agent安装命令':re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash)}
						df = df.append(line,ignore_index=True)
					else: #如果不是二层业务组
						for item3 in html['rows']: 
							if (item3['groupId'] == item2['parentId']):
								if str(item['parentId']) in list2: #如果是三级业务组
									line={'1级业务组':item3['name'],'2级业务组':item2['name'],'3级业务组':item['name'],'agent安装命令':re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash)}
									df = df.append(line,ignore_index=True)
								else: #如果是四级业务组
									for item4 in html['rows']: 
										if (item4['groupId'] == item3['parentId']):
											line={'1级业务组':item4['name'],'2级业务组':item3['name'],'3级业务组':item2['name'],'4级业务组':item['name'],'agent安装命令':re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash)}
											df = df.append(line,ignore_index=True)
	return(df)

def group_to_txt(html,bash,which_os):
	"""
	处理数据，处理包含业务组信息的json，以每个安装命令一个txt文档的方式输出
	input： json数据，agent安装命令，操作系统版本
	output： 1（失败则返回0）
	"""
	list2 = [] #这个list存储所有二级业务组的groupId
	
	for item in html['rows']: 
		if (item['parentId'] == 0):#如果是一层业务组
			i = 1 #确保循环正常运行，无含义
		else:#如果不是一层业务组
			for item2 in html['rows']: 
				if (item2['groupId'] == item['parentId']):
					if (item2['parentId'] == 0):#如果是二层业务组
						list2.append(str(item['groupId']))#向list存储二级业务组的groupId		
	
	try:
		for item in html['rows']:  
			# ~ print(item)
			if (item['parentId'] == 0):#如果是一层业务组
				txtWrite(item['name'],item['name']+"-"+which_os+'agent安装命令',re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash))
			else:#如果不是一层业务组
				for item2 in html['rows']: 
					if (item2['groupId'] == item['parentId']):
						if (item2['parentId'] == 0):#如果是二层业务组
							txtWrite(item2['name']+"-"+item['name'],item2['name']+"-"+item['name']+"-"+which_os+'agent安装命令',re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash))
						else: #如果不是二层业务组
							for item3 in html['rows']: 
								if (item3['groupId'] == item2['parentId']):
									if str(item['parentId']) in list2: #如果是三级业务组
										txtWrite(item3['name']+item2['name']+"-"+item['name'],item3['name']+item2['name']+"-"+item['name']+"-"+which_os+'agent安装命令',re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash))
									else: #如果是四级业务组
										for item4 in html['rows']: 
											if (item4['groupId'] == item3['parentId']):
												txtWrite(item4['name']+item3['name']+item2['name']+"-"+item['name'],item4['name']+item3['name']+item2['name']+"-"+item['name']+"-"+which_os+'agent安装命令',re.sub(r'(group=.*?&)', "group="+str(item['groupId'])+"&", bash))
		logging.info(f'成功输出txt文档')
		return(1)
	except:
		logging.error(f'处理安业务组信息,输出txt文档失败')
		return(0)

	
def txtWrite(filepath,filename,data):
	"""
	输出至txt文件
	input：存储路径,文件名, 待写入的str
	output： 1（失败则返回0）
	"""
	try:		#创建路径
		filepath=filepath.rstrip("\\")
		isExists=os.path.exists(filepath)
		if not isExists:
			os.makedirs(filepath)
		logging.info(f'{filepath}路径创建成功')
	except Exception as e :
		logging.error(f'创建{filepath}路径失败')
		logging.error(e)
		return(0)
		
	try:		#输出数据至txt
		f = open(filepath+'/'+filename,'w+')
		f.write(data)
		f.close()
		logging.info(f'输出结果至txt文件{filepath}/{filename}')
		return(1)
	except:
		try:
			f = open(filepath+'/'+filename,'w+')
			f.write(data.encode('UTF-8', 'ignore').decode('UTF-8'))
			logging.info(f'输出结果至txt文件{filepath}/{filename}')
			return(1)
		except Exception as e :
			logging.error(f'{filepath}/{filename}输出结果至txt文件失败')
			logging.error(e)
			return(0)
		

def api_login(host,port,username,password):
	"""
	获取api登录密钥
	input：java服务器ip，api端口，80用户名，80密码
	output： api登录密钥
	"""
	conn = http.client.HTTPConnection(host, port)
	url = "http://%s:%s/v1/api/auth" % (host, port)
	header = {"Content-Type": "application/json"}
	body = {"username": username, "password": password}
	json_body = json.dumps(body)
	conn.request(method="POST", url=url, body=json_body, headers=header)
	response = conn.getresponse()
	res = response.read()
	return json.loads(res)


def send_request(method, host, port, url, data, api_login):
	"""
	发起api请求
	input：请求方式, java服务器ip，api端口，api的对应url，请求体
	output：请求结果
	"""
	# 参看登录认证里面的登录方法代码示例
	login_result = api_login
	sign_key = login_result.get("data").get("signKey")
	jwt = login_result.get("data").get("jwt")
	comid = login_result.get("data").get("comId")
	
	# 当前时间戳
	ts = int(time.time())
	
	if data is not None:
		info = ""
		if method == "GET":
			# 对参数key进行字典排序
			keys = sorted(data.keys())
			for key in keys:
				info = info + key + str(data.get(key))
				# ~ print(info)
		elif method == "POST" or method == "PUT" or method == "DELETE":
			info = json.dumps(data)
		# 拼接待签名字符串
		to_sign = comid + info + str(ts) + sign_key
	else:
		# 拼接待签名字符串
		to_sign = comid + str(ts) + sign_key
	
	# 对待签名字符串进行sha1得到签名字符串
	sign = hashlib.sha1(to_sign.encode("utf-8")).hexdigest()

	# 组装http请求头参数
	header = {"Content-Type": "application/json", "comId": comid, "timestamp": ts,
			  "sign": sign, "Authorization": "Bearer " + jwt}
	
	conn = http.client.HTTPConnection(host, port)
	conn.request(method=method, url=url, body=json.dumps(data), headers=header)
	response = conn.getresponse()
	res = response.read()
	return res


def get_webshell_list(host, port, api_key, osType):
	"""
	获取所有webshell列表,最 多支持导出2w个最新的
	input：java服务器ip，api端口，api_key, 操作系统(win|linux)
	output：list格式的请求结果
	"""
	url = "http://%s:%s/external/api/websecurity/webshell/%s?page=0&size=20000" % (host, port, osType)
	data = {'page': 0, 'size': 20000}
	res = send_request("GET", host, port, url, data, api_key) #res此时是字符串类型
	res = json.loads(res) #将res转换为json格式
	json_dicts=json.dumps(res, indent=4, separators=(',', ':'))  
	return(res["rows"])

def download_webshell(host, port, api_key, osType, webshell_list):
	"""
	下载webshell
	input：java服务器ip，api端口，api_key, 操作系统(win|linux),webshell文件id列表
	output：执行结果,成功1,失败0
	"""
	try:
		for shell in webshell_list:
			try:
				shell_id=shell["id"]
				url = f"http://{host}:{port}/external/api/websecurity/webshell/{osType}/download/{shell_id}"
				data = {}
				res = send_request("GET", host, port, url, data, api_key) #res此时是字符串类型
				# ~ print(res)
				res = json.loads(res) #将res转换为json格式
				json_dicts=json.dumps(res["content"], indent=4, separators=(',', ':'))  
				regexDesc = "主机IP:"+shell["displayIp"]+"\r\n文件路径:"+shell["filePath"]+"\r\n后门类型:"+str(shell["typeDesc"])+"\r\n触发告警的特征代码:"+str(shell["regexDesc"])
				txtWrite(f"{osType}-webshell/{res['fileName']}".encode('raw_unicode_escape').decode(), shell["fileMd5"], json_dicts.encode('utf8').decode('unicode_escape'))
				txtWrite(f"{osType}-webshell/{res['fileName']}".encode('raw_unicode_escape').decode(), shell["fileMd5"]+"检测说明", regexDesc)
			except Exception as e:
				logging.error(f"下载{res['fileName']}webshell失败")
				logging.error(e)
		return(1)
	except:
		logging.error(f'下载{osType}webshell失败')
		return(0)
		

def crawler(ip, url, Cookie, data):
	"""
	爬虫功能实现入口
	input：url , SESSION_ID Cookie, 请求体(dict格式)
	output：请求结果
	"""
	headers = {
	"Content-Type": "application/json;charset=UTF-8",
	"Origin": f"http://{ip}",
	"Referer": f"http://{ip}/v3/",
    "Cookie": f"SESSION_ID={Cookie}" ,
    }
	
	
	# ~ proxy={'http':'http://192.168.194.142:8081'}
	post_param = json.dumps(data)
	
	
	# ~ html = requests.post(url=url, data=post_param, headers=headers,proxies=proxy).json()
	html = requests.post(url=url, data=post_param, headers=headers).json()
	return(html)

def download(ip, url, Cookie, data):
	"""
	文件下载功能实现入口
	input：php ip ,url , SESSION_ID Cookie, 请求体(dict格式)
	output：请求结果
	"""
	headers = {
	"Content-Type": "application/x-www-form-urlencoded",
	"Origin": f"http://{ip}",
	"Referer": f"http://{ip}/v3/",
    "Cookie": f"SESSION_ID={Cookie}" ,
    }
	
	# ~ proxy={'http':'http://192.168.194.7:8081'}
	# ~ html = requests.post(url=url, data=data, headers=headers,proxies=proxy)
	html = requests.post(url=url, data=data, headers=headers)
	# ~ print(html)
	return(html)


def download_backdoor(ip, Cookie, deadline):
	"""
	批量下载一段时间内发现的后门文件
	input：php ip, url , SESSION_ID Cookie ,截至日期
	output：执行结果,成功1,失败0
	"""
	date={"search":{},"orders":[{"ascend":"false","field":"createTime"}],"page":1,"size":20000,"filters":["group"]}
	
	#windows
	html = crawler(ip, f'http://{ip}/v1/assets/win/backdoor/list', Cookie, date)
	for i in html["data"]["rows"]:
		filepath = "win-backdoor/"+i["displayIp"]
		if  datetime.datetime.utcfromtimestamp(i["createTime"]) > deadline :
			if i["download"]==True :  #判断告警是否包含可下载的文件,若存在可下载文件，下载它
				data = f"data=%7B%22id%22%3A%22{i['id']}%22%7D"
				url = f"http://{ip}/v1/assets/win/backdoor/download"
				# ~ a=json.dumps(data)
				a = download(ip, url, Cookie, data)
				try:		#创建路径
					filepath=filepath.rstrip("\\")
					isExists=os.path.exists(filepath)
					if not isExists:
						os.makedirs(filepath)
					logging.info(f'{filepath}路径创建成功')
				except:
					logging.error(f'创建{filepath}路径失败')
					return(0)
				with open(filepath+f'/病毒样本!:{i["description"]}', "wb") as code:
					code.write(a.content)
				
		#无论是否下载了病毒样本，都下载后门说明
			data = {"id":i["id"],"viewType":"1"}
			a = crawler(ip, f"http://{ip}/v1/assets/win/backdoor/detail", Cookie, data)
			txtWrite(filepath,f'/告警详情!:{i["description"]}.txt',str(a))
	
	
	#linux
	html = crawler(ip, f'http://{ip}/v1/assets/linux/backdoor2/list', Cookie, date)
	for i in html["data"]["rows"]:
		filepath = "linux-backdoor/"+i["displayIp"]
		if datetime.datetime.utcfromtimestamp(i["createTime"]) > deadline : 
			if i["download"]==True :  #判断告警是否包含可下载的文件,若存在可下载文件，下载它
				data = f"data=%7B%22id%22%3A%22{i['id']}%22%7D"
				url = f"http://{ip}/v1/assets/linux/backdoor2/download"
				a = download(ip, url, Cookie, data)
				try:		#创建路径
					filepath=filepath.rstrip("\\")
					isExists=os.path.exists(filepath)
					if not isExists:
						os.makedirs(filepath)
					logging.info(f'{filepath}路径创建成功')
				except:
					logging.error(f'创建{filepath}路径失败')
					return(0)
				with open(filepath+f'/病毒样本!:{i["description"]}', "wb") as code:
					code.write(a.content)
		
			#无论是否下载了病毒样本，都下载后门说明
			data = {"id":i["id"],"viewType":"1"}
			a = crawler(ip, f"http://{ip}/v1/assets/linux/backdoor2/detail", Cookie, data)
			txtWrite(filepath,f'/告警详情!:{i["description"]}.txt',str(a))
		
		
def get_backdoor_list(host, port, api_key, osType):
	"""
	获取所有后门检测列表,最 多支持导出2w个最新的
	input：java服务器ip，api端口，api_key, 操作系统(win|linux)
	output：list格式的请求结果
	"""
	url = "http://%s:%s/external/api/detect/backdoor/%s?page=0&size=20000" % (host, port, osType)
	data = {'page': 0, 'size': 20000}
	res = send_request("GET", host, port, url, data, api_key) #res此时是字符串类型
	res = json.loads(res) #将res转换为json格式
	json_dicts=json.dumps(res, indent=4, separators=(',', ':'))  
	return(res["rows"])

	

def agent_install_main(filename):
	"""
	agent安装主方法
	input：ip列表.csv
	output： 安装结果.csv
	"""
	bash = input('输入Linux安装命令：')
	df=CSVRead(filename)
	result={}
	for index, row in df.iterrows():
		js={"IP":row['IP'],"agent安装结果":"","网络联通性":"","agent运行状态":"","是否成功下载agent错误日志":""}
		# ~ js=json.loads(js)  #创建字典，存储安装结果
		print(f'=================开始为{row["IP"]}安装agent===============')
		logging.info(f'=================开始为{row["IP"]}安装agent===============')
		SSHLinux(row['IP'],row['端口'],row['用户名'],row['ssh密码'],"mv /var/log/titanagent/install.log /var/log/titanagent/install.log_"+str(time.time())+"bak")
		txt=SSHLinux(row['IP'],row['端口'],row['用户名'],row['ssh密码'],bash)
		logging.info(txt)
		if (len(str(txt))<5):		#ssh连接失败
			js["agent安装结果"]="ssh登录失败"
			print("ssh登录失败")
			check_link=check_link_status(row['IP'],row['端口'])
			js["网络联通性"]=check_link
		else:		#ssh连接成功
			js["网络联通性"]="良好"
			print("网络可达")
			time.sleep(5)
			status=check_agent_status(row['IP'],row['端口'],row['用户名'],row['ssh密码'])
			# ~ print("status="+str(status))
			if(status==2):		#安装失败
				logging.info(f'{row["IP"]}安装失败')
				js["agent安装结果"]="安装失败"
				if(txt==2):
					js["agent安装结果"]="命令执行超时,可能是agent和服务端无法通信,请查看agent网络需求文档"
				print("安装失败")
				txt=SSHLinux(row['IP'],row['端口'],row['用户名'],row['ssh密码'],"cat /var/log/titanagent/install.log")
				if(txt!=0 and txtWrite(row['IP'],"install.log",txt)):
					js["是否成功下载agent错误日志"]="成功"
					print("成功下载agent错误日志")
					reason=check_reason_for_installation_failure(txt)
					js["agent安装结果"]=reason
					# ~ print(reason)
				else:
					js["是否成功下载agent错误日志"]="失败"
					print("无法下载agent错误日志")
			elif(status==0):		#安装成功但agent运行异常
				logging.info(f'{row["IP"]}安装失败')
				js["agent安装结果"]="成功"
				js["agent运行状态"]="异常"
				print("安装成功,但运行异常")
				txt=SSHLinux(row['IP'],row['端口'],row['用户名'],row['ssh密码'],"tail -n 4000 /var/log/titanagent/sys.log")
				if(txt!=0 and txtWrite(row['IP'],"sys.log",txt)):
					js["是否成功下载agent错误日志"]="成功"
					print("成功下载agent错误日志")
				else:
					js["是否成功下载agent错误日志"]="失败"
					print("无法下载agent错误日志")
			elif(status==1):		#agent运行正常
				logging.info(f'{row["IP"]}安装成功')
				js["agent安装结果"]="成功"
				print("agent安装成功")
				js["agent运行状态"]="良好"
				js["是否成功下载agent错误日志"]="无需下载"		
		result[index]=js
		logging.info(js)
			
	df = pd.DataFrame.from_dict(result, orient='index')
	CSVWrite("csv","Installation_result.csv",df)
	print("安装完成，输出结果至 Installation_result.csv")
			



def backdoor_download_main(): #后门批量下载程序主入口
	ip = input('输入 80前台ip:\r\n')
	cookie = input('输入 80前台 SESSION_ID Cookie:\r\n')
	deadline = input('需要下载 几天之内 发现的webshell?\r\n')

	
	deadline = datetime.datetime.today()-datetime.timedelta(days=int(deadline))
	
	#下载后门文件&详情
	download_backdoor(ip, cookie, deadline)
	print(f'下载完成, 请查看 [win|linux]backdoor 文件夹')




	
def webshell_download_main(): #webshell批量下载程序主入口
	host = input('输入java服务器ip:\r\n')	
	port = input('输入api端口, 一般在这里输入6000:\r\n')	
	username = input('输入 80前台账号:\r\n')	
	passwd = input('输入 80前台密码:\r\n')	
	deadline = input('需要下载 几天之内 发现的webshell?\r\n')	

	

	deadline = datetime.datetime.today()-datetime.timedelta(days=int(deadline))
	api_key=api_login(host, port, username, passwd)
	
	a = get_webshell_list(host, port, api_key, "win")
	if a is not None:
		for i in range(len(a)-1, -1, -1):
			print(datetime.datetime.utcfromtimestamp(a[i]["createTime"]))
			# ~ print(deadline)
			# ~ print(datetime.datetime.utcfromtimestamp(a[i]["createTime"]) > deadline)
			if datetime.datetime.utcfromtimestamp(a[i]["createTime"]) > deadline:
				a.pop(i)
		# ~ print(a)
		if a is not None:
			len_a = len(a)
		else:
			len_a = 0
		download_webshell(host, port, api_key, "win" , a)
	else:
		len_a = 0
		
	b = get_webshell_list(host, port,  api_key, "linux")
	print(type(deadline))
	if b is not None:
		for i in range(len(b)-1, -1, -1):
			if datetime.datetime.utcfromtimestamp(b[i]["createTime"]) > deadline:
				b.pop(i)	
		# ~ print(b)
		if b is not None:
			len_b = len(b)
		else:
			len_b = 0
		download_webshell(host, port, api_key, "linux" , b)
	else:
		len_b = 0
		
	print(f'下载完成,共下载{len_a+len_b}个webshell,请查看 [win|linux]webshell 文件夹')
	


def agent_Install_command_main(): #agent安装命令导出主入口
	ip = input('输入万相服务端ip：')
	cookie = input('输入SESSION_ID cookie：')
	osType = input('导出哪个操作系统的安装命令（win/linux）：')
	bash = input(f'输入任意业务组的{osType} agent安装命令：')
	

	
	
	html = get_all_group(ip,cookie,osType)
	print('1-以每个安装命令一个txt文档的方式输出')
	print('2-以所有安装命令在同一个csv文档中的方式导出')
	out = input('选择本次导出为以上哪种格式：')
	if(out=="1"):
		group_to_txt(html,bash,osType)
		print('输出txt文档,请查看脚本所在目录')
	elif(out=="2"):	
		# ~ print (html)
		df = group_to_DF(html,bash)
		CSVWrite(f"agent_Install_command",f"{ip}-{osType}.csv",df)
		print('输出csv文档,请查看脚本所在目录/agent_Install_command/')
	



if __name__ == '__main__':        #程序运行入口
	logging.basicConfig(level=logging.INFO,filename='main.log',format="%(asctime)s:%(levelname)s:%(message)s")
	logging.info(f'----------------------程序启动----------------------')
	print('目前支持的任务：')
	print('1-批量安装agent')
	print('2-导出所有业务组的agent安装命令')
	print('3-下载最近一段时间发现的webshell, 并导出webshell告警详情')
	print('4-下载最近一段时间发现的后门, 并导出后门检测告警详情')
	bash = input('输入本次执行任务的编号：')
	if(bash=="1"):
		agent_install_main("ip.csv")
	elif(bash=="2"):	
		agent_Install_command_main()
	elif(bash=="3"):	
		webshell_download_main()
	elif(bash=="4"):
		backdoor_download_main()

