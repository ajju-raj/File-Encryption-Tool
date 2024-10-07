import React, { useState } from 'react';
import axios from 'axios';

const FileEncryptionApp = () => {
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState('');
  const [downloadUrl, setDownloadUrl] = useState('');
  const [key, setKey] = useState('');
  const [iv, setIv] = useState('');
  const [mode, setMode] = useState('encrypt'); // 'encrypt' or 'decrypt'

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleEncrypt = async (e) => {
    e.preventDefault();
    if (!file) {
      setMessage('Please select a file.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('http://localhost:5000/encrypt', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setMessage('File encrypted successfully!');
      setDownloadUrl(`http://localhost:5000${response.data.downloadUrl}`);
      setKey(response.data.key);
      setIv(response.data.iv);
    } catch (error) {
      setMessage('Error encrypting file.');
    }
  };

  const handleDecrypt = async (e) => {
    e.preventDefault();
    if (!file || !key || !iv) {
      setMessage('Please provide a file, key, and IV.');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('key', key);
    formData.append('iv', iv);

    try {
      const response = await axios.post('http://localhost:5000/decrypt', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setMessage('File decrypted successfully!');
      setDownloadUrl(`http://localhost:5000${response.data.downloadUrl}`);
    } catch (error) {
      setMessage('Error decrypting file.');
    }
  };

  const handleDownload = () => {
    if (downloadUrl) {
      window.location.href = downloadUrl;
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>File Encryption/Decryption Tool</h1>
        <div style={styles.modeSelector}>
          <button 
            style={mode === 'encrypt' ? styles.activeMode : styles.inactiveMode} 
            onClick={() => setMode('encrypt')}
          >
            Encrypt
          </button>
          <button 
            style={mode === 'decrypt' ? styles.activeMode : styles.inactiveMode} 
            onClick={() => setMode('decrypt')}
          >
            Decrypt
          </button>
        </div>
        <form onSubmit={mode === 'encrypt' ? handleEncrypt : handleDecrypt} style={styles.form}>
          <label style={styles.label}>Select a file:</label>
          <input type="file" onChange={handleFileChange} style={styles.fileInput} />
          {mode === 'decrypt' && (
            <>
              <label style={styles.label}>Key:</label>
              <input type="text" value={key} onChange={(e) => setKey(e.target.value)} style={styles.textInput} />
              <label style={styles.label}>IV:</label>
              <input type="text" value={iv} onChange={(e) => setIv(e.target.value)} style={styles.textInput} />
            </>
          )}
          <button type="submit" style={styles.button}>
            {mode === 'encrypt' ? 'Encrypt & Upload' : 'Decrypt & Download'}
          </button>
        </form>
        {message && <p style={styles.message}>{message}</p>}
        {downloadUrl && (
          <button onClick={handleDownload} style={styles.downloadBtn}>Download File</button>
        )}
        {mode === 'encrypt' && key && (
          <div style={styles.keyInfo}>
            <h3 style={styles.keyInfoTitle}>Encryption Details</h3>
            <p style={styles.keyInfoText}><strong>Key:</strong> {key}</p>
            <p style={styles.keyInfoText}><strong>IV:</strong> {iv}</p>
            <p style={styles.warning}>Save these for decryption!</p>
          </div>
        )}
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#f0f2f5',
    fontFamily: 'Arial, sans-serif',
  },
  card: {
    backgroundColor: '#ffffff',
    borderRadius: '12px',
    padding: '40px',
    width: '480px',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
  },
  title: {
    fontSize: '28px',
    color: '#333',
    marginBottom: '24px',
    textAlign: 'center',
  },
  modeSelector: {
    display: 'flex',
    justifyContent: 'center',
    marginBottom: '24px',
  },
  activeMode: {
    padding: '10px 20px',
    backgroundColor: '#4CAF50',
    color: '#fff',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    marginRight: '10px',
    transition: 'background-color 0.3s',
  },
  inactiveMode: {
    padding: '10px 20px',
    backgroundColor: '#f0f0f0',
    color: '#333',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    marginRight: '10px',
    transition: 'background-color 0.3s',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    marginBottom: '24px',
  },
  label: {
    marginBottom: '8px',
    color: '#555',
    fontSize: '14px',
  },
  fileInput: {
    marginBottom: '16px',
    padding: '8px',
    border: '1px solid #ddd',
    borderRadius: '4px',
  },
  textInput: {
    marginBottom: '16px',
    padding: '10px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontSize: '14px',
  },
  button: {
    padding: '12px 20px',
    backgroundColor: '#4CAF50',
    color: '#fff',
    border: 'none',
    borderRadius: '5px',
    cursor: 'pointer',
    fontSize: '16px',
    transition: 'background-color 0.3s',
  },
  downloadBtn: {
    backgroundColor: '#007bff',
    color: '#fff',
    padding: '12px 20px',
    borderRadius: '5px',
    cursor: 'pointer',
    border: 'none',
    fontSize: '16px',
    transition: 'background-color 0.3s',
  },
  message: {
    color: '#4CAF50',
    marginBottom: '16px',
    textAlign: 'center',
    fontSize: '14px',
  },
  keyInfo: {
    marginTop: '24px',
    backgroundColor: '#f9f9f9',
    padding: '16px',
    borderRadius: '8px',
    border: '1px solid #ddd',
  },
  keyInfoTitle: {
    fontSize: '18px',
    color: '#333',
    marginBottom: '12px',
  },
  keyInfoText: {
    fontSize: '14px',
    color: '#555',
    marginBottom: '8px',
    wordBreak: 'break-all',
  },
  warning: {
    color: '#d32f2f',
    fontWeight: 'bold',
    marginTop: '12px',
    fontSize: '14px',
  },
};

export default FileEncryptionApp;