import { MongoClient } from 'mongodb';

class DBClient {
  constructor() {
    const port = process.env.DB_PORT || 27017;
    const host = process.env.DB_HOST || 'localhost';
    const dbName = process.env.DB_NAME || 'files_manager';
    const url = `mongodb://${host}:${port}/${dbName}`;
    this.client = new MongoClient(url);
    this.client.connect();
  }

  isAlive() {
    return this.client.isConnected();
  }

  async nbUsers() {
    const collection = this.client.db().collection('users');
    return collection.countDocuments();
  }

  async nbFiles() {
    const collection = this.client.db().collection('files');
    return collection.countDocuments();
  }
}

const dbClient = new DBClient();

export default dbClient;
