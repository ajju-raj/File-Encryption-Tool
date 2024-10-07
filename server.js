const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();

app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json());

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

const algorithm = 'aes-256-ctr';

function encryptFile(fileBuffer, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, 'hex'), iv);
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  return { iv: iv.toString('hex'), encrypted };
}

function decryptFile(encryptedBuffer, key, iv) {
  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
  const decrypted = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
  return decrypted;
}

app.post('/encrypt', upload.single('file'), (req, res) => {
  const file = req.file;
  
  if (!file) {
    return res.status(400).send('No file uploaded.');
  }

  const filePath = path.join(__dirname, '/uploads/', file.filename);
  const fileBuffer = fs.readFileSync(filePath);

  const key = crypto.randomBytes(32).toString('hex');
  const { iv, encrypted } = encryptFile(fileBuffer, key);

  const encryptedFilename = `enc_${file.filename}`;
  const encryptedFilePath = path.join(__dirname, '/uploads/', encryptedFilename);
  fs.writeFileSync(encryptedFilePath, encrypted);

  res.json({
    message: 'File encrypted successfully',
    downloadUrl: `/download/${encryptedFilename}`,
    key: key,
    iv: iv,
  });
});

app.post('/decrypt', upload.single('file'), (req, res) => {
  const file = req.file;
  const { key, iv } = req.body;

  if (!file || !key || !iv) {
    return res.status(400).send('File, key, and IV are required.');
  }

  const filePath = path.join(__dirname, '/uploads/', file.filename);
  const encryptedBuffer = fs.readFileSync(filePath);

  try {
    const decrypted = decryptFile(encryptedBuffer, key, iv);
    
    const decryptedFilename = `dec_${file.originalname}`;
    const decryptedFilePath = path.join(__dirname, '/uploads/', decryptedFilename);
    fs.writeFileSync(decryptedFilePath, decrypted);

    res.json({
      message: 'File decrypted successfully',
      downloadUrl: `/download/${decryptedFilename}`
    });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).send('Error decrypting file');
  }
});

app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'uploads', filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }

  res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
  res.setHeader('Content-Type', 'application/octet-stream');

  const fileStream = fs.createReadStream(filePath);
  fileStream.pipe(res);
});

if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

app.get('/', (req, res) => {
  res.send('File Encryption Tool Backend is Running');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Serving files from: ${path.join(__dirname, 'uploads')}`);
});