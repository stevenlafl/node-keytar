const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

function checkRequired(val, name) {
  if (!val || val.length <= 0) {
    throw new Error(name + ' is required.');
  }
}

// Serves as a drop-in replacement for keytar C++ bindings, written in pure node.js.
class credentialStore {

  constructor(filePath, key) {
    this.algorithm = 'aes-256-ctr';
    this.iv = null;
    this.secretKey = null;

    if (key) {
      this.secretKey = crypto.scryptSync(key, 'salt', 32);
    }

    this.filePath = filePath;
    this.load();
  }

  async setPassword(service, account, password) {
    this.throwIfObject(service, account, password);

    let serviceMap = this.services.get(service) || new Map();
    serviceMap.set(account, password);

    this.services.set(service, serviceMap);
    this.save();
  }

  async getPassword(service, account) {
    this.throwIfObject(service, account);

    let serviceMap = this.services.get(service);
    if (serviceMap && serviceMap.has(account)) {
      return serviceMap.get(account) || null;
    }

    return null;
  }

  async deletePassword(service, account) {
    this.throwIfObject(service, account);

    let serviceMap = this.services.get(service);
    if (serviceMap && serviceMap.has(account)) {
      serviceMap.delete(account);

      this.services.set(service, serviceMap);
      this.save();
      return true;
    }

    return false;
  }

  async findPassword(service) {
    this.throwIfObject(service);

    let serviceMap = this.services.get(service);
    if (serviceMap) {
      return serviceMap.values().next().value;
    }

    return null;
  }

  async findCredentials(service) {
    this.throwIfObject(service);

    let serviceMap = this.services.get(service);

    let retVal = [];
    if (serviceMap) {

      for (const [k, v] of serviceMap.entries()) {
        retVal.push({
          account: k,
          password: v
        });
      }
    }

    return retVal;
  }

  throwIfObject(service, account, password) {
    if (service instanceof Object) {
      throw new Error("Parameter 'service' must be a string");
    }
    if (account instanceof Object) {
      throw new Error("Parameter 'username' must be a string");
    }
    if (password instanceof Object) {
      throw new Error("Parameter 'password' must be a string");
    }
  }

  saveData() {
    let data = {services: []}
    for (const [serviceName, serviceMap] of this.services.entries()) {
      let services = {};
      services.key = serviceName;
      services.value = [];

      for (const [accountName, accountPassword] of serviceMap.entries()) {
        let account = {};
        account.key = accountName;
        account.value = accountPassword;

        services.value.push(account);
      }

      data.services.push(services);
    }

    return data;
  }

  loadData(data) {
    if (data.services) {
      let serviceMap = new Map();
      for (const service of data.services) {
        let accountMap = new Map();
        for (const account of service.value) {
          accountMap.set(account.key, account.value);
        }
        serviceMap.set(service.key, accountMap);
      }

      return serviceMap;
    }
  }

  save() {
    if (this.secretKey) {
      this.saveEncrypted();
    }
    else {
      this.saveUnencrypted();
    }
  }

  load() {
    if (this.secretKey) {
      this.loadEncrypted();
    }
    else {
      this.loadUnencrypted();
    }
  }

  saveUnencrypted() {
    let data = this.saveData();
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(data), "utf8");
    }
    catch (e) {
      console.error(e);
    }
  }

  loadUnencrypted() {
    try {
      let contents = JSON.parse(fs.readFileSync(this.filePath, "utf8"));

      if (contents.iv) {
        // We can't decrypt. Erase and start over.
        this.services = new Map();
        return;
      }

      let data = this.loadData(contents);
      this.services = data;

      return;
    }
    catch(e) {
      console.error(e);
    }
    
    this.services = new Map();
  }

  saveEncrypted() {
    let data = this.saveData();
    let contents = JSON.stringify(data);
    let secrets = this.encrypt(contents);
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(secrets), "utf8");
    }
    catch (e) {
      console.error(e);
    }
  }

  loadEncrypted() {
    try {
      let secrets = fs.readFileSync(this.filePath, "utf8");
      
      let hash = JSON.parse(secrets);

      if (hash.iv) {
        this.iv = Buffer.from(hash.iv.data)

        let contents = this.decrypt(hash);
        let data = this.loadData(JSON.parse(contents));

        this.services = data;
      }
      else if (hash.services) {
        // Attempt to recover data.
        loadUnencrypted();
        this.iv = crypto.randomBytes(16);
      }

      return;
    }
    catch(e) {
      console.error(e);
    }
    
    this.services = new Map();
    this.iv = crypto.randomBytes(16);
  }

  encrypt(text) {
    
    const cipher = crypto.createCipheriv(this.algorithm, Buffer.from(this.secretKey), this.iv);
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

    return {
      iv: this.iv,
      contents: encrypted.toString('hex')
    }
  };

  decrypt(hash) {
    const decipher = crypto.createDecipheriv(this.algorithm, Buffer.from(this.secretKey), this.iv);
    const decrypted = Buffer.concat([decipher.update(Buffer.from(hash.contents, 'hex')), decipher.final()]);

    return decrypted.toString();
  };
}

let credsDir = os.homedir() + '/.local/creds';
fs.mkdirSync(credsDir, { recursive: true });

keytar = new credentialStore(credsDir + '/keytar.json', process.env.ENCRYPTION_KEY || null);

module.exports = {
  getPassword: function (service, account) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')

    return keytar.getPassword(service, account)
  },

  setPassword: function (service, account, password) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')
    checkRequired(password, 'Password')

    return keytar.setPassword(service, account, password)
  },

  deletePassword: function (service, account) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')

    return keytar.deletePassword(service, account)
  },

  findPassword: function (service) {
    checkRequired(service, 'Service')

    return keytar.findPassword(service)
  },

  findCredentials: function (service) {
    checkRequired(service, 'Service')

    return keytar.findCredentials(service)
  }
}
