# Server Management Guide

## Quick Health Check

Test if your server is running by visiting these URLs in your browser or using curl:

### From your local machine:
```bash
# Health check (should return {"status":"ok","timestamp":...})
curl http://69.164.202.138/health

# Root endpoint (should show API info)
curl http://69.164.202.138/

# Test scan endpoint
curl "http://69.164.202.138/scan?domain=example.com"
```

### From the remote server:
```bash
# Health check
curl http://localhost/health

# Or if you need to specify port 80 explicitly
curl http://localhost:80/health
```

## How to Start the Server

### Option 1: Direct Node.js (for testing)
```bash
cd /path/to/test\ server
node server-improved.js
```

### Option 2: Using npm start
```bash
cd /path/to/test\ server
npm start
```

### Option 3: Using PM2 (Recommended for production - keeps server running)

**Install PM2 globally:**
```bash
npm install -g pm2
```

**Start the server with PM2:**
```bash
cd /path/to/test\ server
pm2 start server-improved.js --name netstar-shield
```

**PM2 Useful Commands:**
```bash
# Check if server is running
pm2 list

# View logs
pm2 logs netstar-shield

# Restart server
pm2 restart netstar-shield

# Stop server
pm2 stop netstar-shield

# Make PM2 start on system reboot
pm2 startup
pm2 save
```

## Check if Server is Running

### Method 1: Check if port 80 is listening
```bash
# On the remote server
sudo netstat -tulpn | grep :80
# or
sudo lsof -i :80
# or
sudo ss -tulpn | grep :80
```

### Method 2: Check Node.js processes
```bash
# Check if node process is running
ps aux | grep node

# Check if PM2 is managing it
pm2 list
```

### Method 3: Test the health endpoint
```bash
# From remote server
curl http://localhost/health

# From your local machine
curl http://69.164.202.138/health
```

## Troubleshooting

### Server not responding?
1. **Check if server process is running:**
   ```bash
   ps aux | grep "server-improved"
   ```

2. **Check server logs:**
   - If running with PM2: `pm2 logs netstar-shield`
   - If running directly: Check the terminal where you started it

3. **Check firewall:**
   ```bash
   # Check if port 80 is open
   sudo ufw status
   # or
   sudo iptables -L
   ```

4. **Check if port 80 requires sudo:**
   - Port 80 requires root privileges
   - You may need to run with `sudo` or use a process manager that handles permissions

### Running on port 80 without sudo
If you can't use sudo, you can:
1. Change PORT to 3000 or another port in server-improved.js
2. Use a reverse proxy (nginx) to forward port 80 to your app port
3. Use `setcap` to allow Node.js to bind to port 80:
   ```bash
   sudo setcap 'cap_net_bind_service=+ep' $(which node)
   ```

## Recommended Setup for Production

1. **Use PM2 to keep server running:**
   ```bash
   npm install -g pm2
   pm2 start server-improved.js --name netstar-shield
   pm2 startup
   pm2 save
   ```

2. **Set up nginx reverse proxy** (if needed for SSL/HTTPS later)

3. **Monitor logs regularly:**
   ```bash
   pm2 logs netstar-shield --lines 100
   ```
