
import pandas as pd
import numpy as np
import re
import openpyxl  # 使用pd.read_excel中需要保证openpyxl库已安装，但可以不导入。 				#读Excel数据用
class Read_data:
    def __init__(self, path = './GPRP/data_cve/fei_cve_20230728.xlsx'):
        self.path = path
        self.all_cve,self.all_payload = self.data()
        self.cve_server, self.cve_switch, self.cve_os, self.cve_database = self.classification()

    def data(self):
        
        data = pd.read_excel(self.path,sheet_name='cve')
        #	data是Excel里的数据
        # print(len(data))
        # print(data.iloc[2,2])
        # h = data.iloc[2,2].split(",")
        # print(type(h))
            
        data_array = np.array(data)
        data_list =data_array.tolist()
        print(type(data_list))
        print(data_list)
        all_cve = {}
        for i in range(len(data)):
            all_cve[data.iloc[i,1]] = {}
            all_cve[data.iloc[i,1]]["id"] = data.iloc[i,0]
            all_cve[data.iloc[i,1]]["targetcategory"] = data.iloc[i,2].split(",")
            all_cve[data.iloc[i,1]]["targetname"] = data.iloc[i,3].split(",")
            all_cve[data.iloc[i,1]]["type"] = data.iloc[i,6]
            all_cve[data.iloc[i,1]]["rule"] = data.iloc[i,10].split(",")
            all_cve[data.iloc[i,1]]["availableexp"] = data.iloc[i,11].split(",")
            all_cve[data.iloc[i,1]]["availablePayload"] = str(data.iloc[i,12]).split(",")
            all_cve[data.iloc[i,1]]["hazardrank"] = data.iloc[i,14]
            #以下是对受影响版本的生成
            num = data.iloc[i,4]
            num5 = re.sub(u"([^\u0030-\u0039\u002e])", " ", str(num))
            i1 = re.split('\s+',num5)
            ls1=[x for x in i1 if x!='' and x != '.']
            ls1_ = []
            for j in ls1:
                if '.' in list(j):
                    ls1_.append(j)
            all_cve[data.iloc[i,1]]["affectedversion"] = ls1_
        # print(all_cve['CVE-2017-12635']["targetcategory"])
        # print(all_cve)

        data_payload = pd.read_excel(self.path,sheet_name='payload')
        all_payload = {}
        for i in range(len(data_payload)):
            all_payload[data_payload.iloc[i,0]] = {}
            all_payload[data_payload.iloc[i,0]]["type"] = data_payload.iloc[i,2]
            all_payload[data_payload.iloc[i,0]]["direction"] = data_payload.iloc[i,3]
            all_payload[data_payload.iloc[i,0]]["score"] = float(data_payload.iloc[i,5])

        #print(type(all_payload["2uJznvpMVbRE7N5Uf9J3UX"]["score"]))

        data_help = pd.read_excel(self.path,sheet_name='ATT')
        # print(data_help.iloc[15,17])
        all_help = {}
        for i in range(len(data_help)):
            all_help[data_help.iloc[i,1]] = {}
            all_help[data_help.iloc[i,1]]["score"] = float(data_help.iloc[i,17])
        # print(all_help)
        for i in all_cve:
            # print(i)
            # print(all_cve[i])
            if i in all_help.keys():
                all_cve[i]["score"] = all_help[i]["score"]
            else:
                all_cve[i]["score"] = 1.0
        # print (all_cve)
        # print(all_cve["CVE-2021-25646"])
        # print(all_help["CVE-2021-25646"])
        return all_cve, all_payload
    
    def classification(self):
        #对漏洞进行一定的分类
        cve_server = {}#针对节点中的软件可能有的漏洞，“应用”、“web”、“协议
        cve_switch = {}#针对交换机可能有的漏洞。“中间件”
        cve_os = {}#针对操作系统可能有的漏洞，“操作系统”
        cve_database = {}#针对数据库可能有的漏洞，“大数据”
        
        for i in self.all_cve:
            # print(self.all_cve[i]['targetcategory'])
            if "middleware" in self.all_cve[i]['targetcategory']:
                cve_switch[i] = self.all_cve[i]
            if "os" in self.all_cve[i]['targetcategory']:
                cve_os[i] = self.all_cve[i]
            if "database" in self.all_cve[i]['targetcategory'] or "bigdata" in self.all_cve[i]['targetcategory']:
                cve_database[i] = self.all_cve[i]
            if "soft" in self.all_cve[i]['targetcategory'] or "Web" in self.all_cve[i]['targetcategory'] or "protocol" in self.all_cve[i]['targetcategory'] or "framework" in self.all_cve[i]['targetcategory']:
                cve_server[i] = self.all_cve[i]
        
        return cve_server,cve_switch,cve_os,cve_database

    
# if __name__ == '__main__':
#     cve_server,cve_switch,cve_os,cve_database = Read_data().classification()
#     # print("cve_server",cve_server.keys())
#     # print("cve_switch",cve_switch.keys())
#     # print("cve_os",cve_os.keys())
#     # print("cve_database",cve_database.keys())
#     cve = Read_data()
#     print("cve_server",cve.all_cve)







    


