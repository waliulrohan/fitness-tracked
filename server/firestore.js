import admin from "firebase-admin"


admin.initializeApp({
  credential: admin.credential.cert(process.env.FIRESTORE_CONFIG)
});

const db = admin.firestore();


export default db;