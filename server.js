const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path'); 
const multer = require('multer');
const crypto = require('crypto'); // 💡 YENİ: Güvenli token oluşturmak için
const bcrypt = require('bcryptjs'); // 💡 YENİ: Güvenli şifreleme için
const markdownit = require('markdown-it');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

// 💡 DÜZELTME: Render gibi platformlar için ortam değişkenini veya varsayılan olarak 3001'i kullan.
const PORT = process.env.PORT || 3001;
const TEAM_ID = 'tek_ekip_sunucusu';
const MAIN_CHANNEL = 'ana-sohbet-kanali'; 
const VOICE_CHANNEL_ID = 'ana-ses-odasi'; 

// Dosya yükleme dizinleri
const uploadsDir = path.join(__dirname, 'uploads');
const avatarsDir = path.join(uploadsDir, 'avatars');
const filesDir = path.join(uploadsDir, 'files'); // 💡 YENİ: Genel dosyalar için yeni klasör

if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);
if (!fs.existsSync(filesDir)) fs.mkdirSync(filesDir); // 💡 YENİ: Klasörü oluştur

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const avatarStorage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, avatarsDir) },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const uploadAvatar = multer({ storage: avatarStorage });

// 💡 YENİ: Genel dosyalar için yeni multer yapılandırması
const fileStorage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, filesDir) },
    filename: function (req, file, cb) {
        // Orijinal dosya adını koruyarak benzersiz bir ön ek ekle
        const uniquePrefix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniquePrefix + '-' + file.originalname);
    }
});
const uploadFile = multer({ storage: fileStorage });

// Yeni Avatar Yükleme Endpoint'i
app.post('/upload-avatar', uploadAvatar.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Dosya yüklenmedi.' });
    }
    // Render'da public URL'yi doğru oluşturmak için
    const host = req.get('host');
    const protocol = req.protocol;
    const avatarUrl = `${protocol}://${host}/uploads/avatars/${req.file.filename}`;
    res.json({ avatarUrl: avatarUrl });
});

// 💡 YENİ: Genel Dosya Yükleme Endpoint'i
app.post('/upload-file', uploadFile.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Dosya yüklenmedi.' });
    }
    const host = req.get('host');
    const protocol = req.protocol;
    const fileUrl = `${protocol}://${host}/uploads/files/${req.file.filename}`;
    res.json({ 
        fileUrl: fileUrl,
        fileName: req.file.originalname, // Orijinal dosya adını geri gönder
        fileType: req.file.mimetype // Dosya türünü geri gönder
    });
});

// --- FIREBASE BAĞLANTISI (RENDER AYARI) ---
let db, auth;
try {
    let serviceAccount;
    // 1. Render Ortam Değişkeninden okumayı dene (deployment ortamı)
    if (process.env.SERVICE_ACCOUNT_JSON) {
        serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_JSON);
    } else {
        // 2. Yerel dosyadan okumayı dene (yerel test ortamı)
        serviceAccount = require('./serviceAccountKey.json');
    }
    
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    db = admin.firestore();
    auth = admin.auth();
    console.log('[SUNUCU] Firebase Admin SDK başarıyla başlatıldı.');

} catch (error) {
    console.error('*****************************************************');
    console.error('[HATA] Firebase başlatılamadı. ServiceAccount Anahtarı eksik/hatalı.', error);
    process.exit(1);
}

// 💡 YENİ: Sunucu başlangıcında varsayılan kanalların varlığını kontrol et
async function ensureDefaultChannels() {
    const textChannelRef = db.collection('channels').doc(MAIN_CHANNEL);
    const voiceChannelRef = db.collection('channels').doc(VOICE_CHANNEL_ID);

    const textDoc = await textChannelRef.get();
    if (!textDoc.exists) {
        console.log(`[SUNUCU] Varsayılan metin kanalı '${MAIN_CHANNEL}' bulunamadı, oluşturuluyor...`);
        await textChannelRef.set({ name: 'genel-sohbet', type: 'text' });
    }
    const voiceDoc = await voiceChannelRef.get();
    if (!voiceDoc.exists) {
        console.log(`[SUNUCU] Varsayılan ses kanalı '${VOICE_CHANNEL_ID}' bulunamadı, oluşturuluyor...`);
        await voiceChannelRef.set({ name: 'Sohbet Odası', type: 'voice' });
    }
}

// Sunucu başladığında bu fonksiyonu çağır
ensureDefaultChannels();

const md = markdownit(); // Markdown parser'ı başlat

const onlineUsers = {};
const userStatus = {};      
const AVATAR_URLS = [ 'https://i.pravatar.cc/150?img=1', 'https://i.pravatar.cc/150?img=2', 'https://i.pravatar.cc/150?img=3', 'https://i.pravatar.cc/150?img=4', 'https://i.pravatar.cc/150?img=5' ];

// 💡 YENİ: Otomatik giriş anahtarlarını saklamak için (bellekte)
const autoLoginTokens = new Map(); // Map<token, uid>

async function handleSuccessfulLogin(socket, uid, rememberMe = false) {
    const userDoc = await db.collection('users').doc(uid).get();
    if (!userDoc.exists) {
        socket.emit('auth error', 'Kullanıcı veritabanında bulunamadı.');
        return;
    }
    const userData = userDoc.data();

    onlineUsers[socket.id] = { ...userData, socketId: socket.id };
    // Durum (presence) özelliği kaldırıldı.
    userStatus[socket.id] = { presence: 'online', muted: false, deafened: false, speaking: false, channel: null }; 

    socket.join(TEAM_ID);
    io.to(TEAM_ID).emit('system message', { message: `${userData.nickname} sohbete katıldı.` });

    let authToken = null;
    if (rememberMe) {
        authToken = crypto.randomBytes(32).toString('hex');
        autoLoginTokens.set(authToken, uid);
    }

    // 💡 YENİ: Kullanıcı ayarlarını al
    const settingsSnap = await db.collection('users').doc(uid).collection('meta').doc('settings').get();
    const userSettings = settingsSnap.exists ? settingsSnap.data() : {};

    // 💡 YENİ: Engellenen kullanıcı listesini al
    const blockedUsersSnap = await db.collection('users').doc(uid).collection('meta').doc('privacy').get();
    const blockedUsers = blockedUsersSnap.exists ? blockedUsersSnap.data().blocked || [] : [];

    socket.emit('login success', { ...userData, authToken, settings: userSettings, blockedUsers });
    console.log(`[SUNUCU] Giriş başarılı: ${userData.nickname}`);

    await Promise.all([ sendChannelList(socket), sendPastMessages(socket, MAIN_CHANNEL), sendDmHistory(socket, uid), getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users)) ]);
    socket.emit('initial data loaded');
}

async function getAllUsers() {
    const allUsersSnapshot = await db.collection('users').get();
    const allUsers = [];

    allUsersSnapshot.forEach(doc => {
        const userData = doc.data();
        const isOnline = Object.values(onlineUsers).some(onlineUser => onlineUser.uid === userData.uid);
        // 💡 DÜZELTME: Kullanıcının socketId'sini doğru şekilde bul.
        const socketId = isOnline ? Object.keys(onlineUsers).find(sid => onlineUsers[sid].uid === userData.uid) : null; 

        allUsers.push({
            uid: userData.uid,
            nickname: userData.nickname,
            avatarUrl: userData.avatarUrl,
            isOnline: isOnline, // 💡 DÜZELTME: isOnline durumu eklendi.
            role: userData.role || 'member', // 💡 YENİ: Kullanıcının rolünü ekle (varsayılan 'member')
            // 💡 DÜZELTME: Ses durumu ile birlikte genel durumu (presence) da gönder
            status: isOnline ? (userStatus[socketId] || { presence: 'online' }) : { presence: 'offline' }
        });
    });

    return allUsers.sort((a, b) => b.isOnline - a.isOnline || a.nickname.localeCompare(b.nickname));
}

io.on('connection', (socket) => {

  // 💡 YENİ: Otomatik Giriş (Middleware gibi çalışır)
  // Bağlantı anında istemciden gelen token'ı kontrol et
  (async () => {
      const token = socket.handshake.auth.token;
      if (token && autoLoginTokens.has(token)) {
          const uid = autoLoginTokens.get(token);
          console.log(`[SUNUCU] Otomatik giriş denemesi başarılı. UID: ${uid}`);
          
          // Eski token'ı silip yenisini oluşturarak güvenliği artır
          autoLoginTokens.delete(token);
          const newAuthToken = crypto.randomBytes(32).toString('hex');
          autoLoginTokens.set(newAuthToken, uid);
          
          // İstemciye yeni token'ı gönder
          socket.emit('token-refreshed', newAuthToken);

          // Normal giriş akışını devam ettir
          await handleSuccessfulLogin(socket, uid, true); // rememberMe: true
          return; // Token ile giriş yapıldıysa, diğer auth olaylarını bekleme
      }
  })();

  // ------------------------------------
  // 0. KAYIT/GİRİŞ (FIREBASE KULLANILDI)
  // ------------------------------------
  
  socket.on('register', async ({ nickname, email, password }) => {
      try {
          if (!nickname || !email || !password) {
              socket.emit('auth error', 'Tüm alanlar zorunludur.');
              return;
          }
          const lcEmail = email.toLowerCase();

          // Aynı e-posta var mı kontrolü (Firestore tarafında)
          const existsQ = await db.collection('users').where('email', '==', lcEmail).limit(1).get();
          if (!existsQ.empty) {
              socket.emit('auth error', 'Bu e-posta adresi zaten kullanılıyor.');
              return;
          }

          const userRecord = await auth.createUser({
              email: lcEmail,
              password: password,
              displayName: nickname,
          });

          const randomAvatar = AVATAR_URLS[Math.floor(Math.random() * AVATAR_URLS.length)];
          // Şifreyi güvenli şekilde hashleyip Firestore'da sakla
          const hashedPassword = await bcrypt.hash(password, 10);
          await db.collection('users').doc(userRecord.uid).set({
              nickname,
              avatarUrl: randomAvatar,
              email: lcEmail,
              uid: userRecord.uid,
              role: 'member', // 💡 YENİ: Kayıt olurken varsayılan rol ata
              // 💡 DÜZELTME: Şifreyi bcrypt ile hash'leyip kaydet.
              password: hashedPassword 
          });

          console.log(`[SUNUCU] Yeni kayıt (Firebase): ${nickname}`);
          socket.emit('auth success', { type: 'register' });

      } catch (err) {
          console.error('Kayıt hatası:', err.message);
          let errorMessage = 'Kayıt sırasında bilinmeyen bir hata oluştu.';
          if (err.code === 'auth/email-already-in-use') { errorMessage = 'Bu e-posta adresi zaten kullanılıyor.'; }
          socket.emit('auth error', errorMessage);
      }
  });

  socket.on('login', async ({ email, password, rememberMe }) => {
      try {
          const userQuery = await db.collection('users').where('email', '==', email.toLowerCase()).limit(1).get();
          if (userQuery.empty) {
               socket.emit('auth error', 'E-posta veya şifre hatalı.');
               return;
          }
          const userDoc = userQuery.docs[0];
          const userData = userDoc.data();

          // 💡 DÜZELTME: Şifre kontrolü eklendi
          const isPasswordMatch = await bcrypt.compare(password, userData.password);
          if (!isPasswordMatch) {
              socket.emit('auth error', 'E-posta veya şifre hatalı.');
              return;
          }
          
          // 💡 YENİ: Başarılı giriş mantığını merkezi fonksiyona taşı
          await handleSuccessfulLogin(socket, userDoc.id, rememberMe);
      } catch (err) {
          // Firebase kimlik doğrulama hatası (örneğin, yanlış şifre)
          console.error('Giriş hatası:', err.code, err.message);
          socket.emit('auth error', 'E-posta veya şifre hatalı.');
      }
  });

  // ------------------------------------
  // PROFİL GÜNCELLEME
  // ------------------------------------
  socket.on('update profile', async ({ newNickname, newAvatarUrl }) => {
    const user = onlineUsers[socket.id];
    if (!user) return;

    try {
        const userRef = db.collection('users').doc(user.uid);
        const userDoc = await userRef.get();
        const currentData = userDoc.data();
        
        const updateData = {
            nickname: newNickname || currentData.nickname,
            avatarUrl: newAvatarUrl || currentData.avatarUrl
        };
        await userRef.update(updateData);

        user.nickname = updateData.nickname;
        user.avatarUrl = updateData.avatarUrl;
        
        // Firebase Auth tarafını da güncelle
        await auth.updateUser(user.uid, { displayName: updateData.nickname, photoURL: updateData.avatarUrl });
        
        socket.emit('profile update success', { nickname: user.nickname, avatarUrl: user.avatarUrl });
        // Profil güncellendiğinde tüm kullanıcılara listeyi tekrar gönder
        getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users));

    } catch(err) {
        console.error('Profil güncelleme hatası:', err.message);
        // 💡 YENİ: Hata mesajını istemciye gönder
        socket.emit('system error', 'Profil güncellenirken bir hata oluştu.');
    }
  });

  // 💡 YENİ: Mesaj tepkisi ekleme/kaldırma
  socket.on('message reaction', async ({ messageId, emoji }) => {
    const user = onlineUsers[socket.id];
    if (!user) return;

    const messageRef = db.collection('messages').doc(messageId);

    try {
      await db.runTransaction(async (transaction) => {
        const messageDoc = await transaction.get(messageRef);
        if (!messageDoc.exists) return;

        const data = messageDoc.data();
        const reactions = data.reactions || {};
        
        if (!reactions[emoji]) {
          reactions[emoji] = [];
        }

        const userIndex = reactions[emoji].indexOf(user.uid);
        if (userIndex > -1) {
          // Kullanıcı zaten bu emoji ile tepki vermiş, tepkisini kaldır
          reactions[emoji].splice(userIndex, 1);
          if (reactions[emoji].length === 0) {
            delete reactions[emoji];
          }
        } else {
          // Kullanıcı yeni tepki veriyor
          reactions[emoji].push(user.uid);
        }
        transaction.update(messageRef, { reactions });
        io.to(TEAM_ID).emit('reaction update', { messageId, reactions });
      });
    } catch (error) {
      console.error('Tepki işlenirken hata:', error);
    }
  });

  // 💡 YENİ: Mesaj silme
  socket.on('delete message', async (messageId) => {
    const user = onlineUsers[socket.id];
    if (!user) return;

    const messageRef = db.collection('messages').doc(messageId);
    try {
      const doc = await messageRef.get();
      if (doc.exists && doc.data().senderUid === user.uid) {
        await messageRef.delete();
        io.to(TEAM_ID).emit('message deleted', { messageId });
      } else {
        // Yetkisiz silme denemesi
        socket.emit('system error', 'Bu mesajı silme yetkiniz yok.');
      }
    } catch (error) {
      console.error('Mesaj silinirken hata:', error);
    }
  });

  // 💡 YENİ: Mesaj düzenleme
  socket.on('edit message', async ({ messageId, newMessage }) => {
    const user = onlineUsers[socket.id];
    if (!user) return;

    const messageRef = db.collection('messages').doc(messageId);
    try {
      const doc = await messageRef.get();
      if (doc.exists && doc.data().senderUid === user.uid) {
        const sanitizedMessage = md.renderInline(newMessage);
        await messageRef.update({ message: sanitizedMessage, edited: true });
        io.to(TEAM_ID).emit('message edited', { messageId, newMessage: sanitizedMessage });
      }
    } catch (error) {
      console.error('Mesaj düzenlenirken hata:', error);
    }
  });

  // ------------------------------------
  // KANAL YÖNETİMİ
  // ------------------------------------
  socket.on('create-channel', async ({ name, type }) => {
    // 💡 YENİ: Yetki Kontrolü
    const user = onlineUsers[socket.id];
    if (!user || user.role !== 'admin') {
      socket.emit('system error', 'Kanal oluşturma yetkiniz yok.');
      return;
    }

    if (!name || (type !== 'text' && type !== 'voice')) {
      // Geçersiz istek, belki bir hata mesajı gönderilebilir.
      return;
    }

    try {
      // Yetki kontrolü başarılı, kanalı oluştur.
      const docRef = await db.collection('channels').add({ name, type });
      const newChannel = { id: docRef.id, name, type };
      io.to(TEAM_ID).emit('channel-created', newChannel);
    } catch (error) {
      console.error('Kanal oluşturma hatası:', error);
    }
  });

  socket.on('delete-channel', async (channelId) => {
    // 💡 YENİ: Yetki Kontrolü
    const user = onlineUsers[socket.id];
    if (!user || user.role !== 'admin') {
      socket.emit('system error', 'Kanal silme yetkiniz yok.');
      return;
    }

    try {
      // Yetki kontrolü başarılı, kanalı sil.
      await db.collection('channels').doc(channelId).delete();
      io.to(TEAM_ID).emit('channel-deleted', channelId);
    } catch (error) {
      console.error('Kanal silme hatası:', error);
    }
  });

  socket.on('join voice channel', async (channelId) => {
    const user = onlineUsers[socket.id];
    if (!user) return;

    userStatus[socket.id].channel = channelId;
    socket.join(channelId);
    socket.to(channelId).emit('user joined', socket.id);
    console.log(`[SUNUCU] ${user.nickname} (${socket.id}) ses kanalına katıldı: ${channelId}`);

    // 💡 YENİ: Sesli kanala katılma mesajını metin kanalına gönder
    try {
        const channelDoc = await db.collection('channels').doc(channelId).get();
        const channelName = channelDoc.exists ? channelDoc.data().name : channelId;
        const systemMessage = `${user.nickname}, '${channelName}' sesli kanalına katıldı.`;
        // Mesajı ana metin kanalına gönderiyoruz.
        io.to(TEAM_ID).emit('system message', { message: systemMessage, channel: MAIN_CHANNEL });
    } catch (error) { console.error('Sesli kanal katılma mesajı gönderilirken hata:', error); }

    // Kanaldaki diğer kullanıcıları yeni katılan kullanıcıya gönder
    const usersInChannel = Object.values(onlineUsers).filter(u => userStatus[u.socketId] && userStatus[u.socketId].channel === channelId && u.socketId !== socket.id);
    socket.emit('ready to talk', usersInChannel.map(u => u.socketId));

    getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users)); // Kullanıcı listesini güncelle
  });

  socket.on('leave voice channel', async (channelId) => {
    const user = onlineUsers[socket.id];
    if (!user) return;

    userStatus[socket.id].channel = null;
    userStatus[socket.id].speaking = false; // Kanaldan ayrılınca konuşma durumunu sıfırla
    socket.leave(channelId);
    console.log(`[SUNUCU] ${user.nickname} (${socket.id}) ses kanalından ayrıldı: ${channelId}`);
    socket.to(channelId).emit('user left', socket.id);

    // 💡 YENİ: Sesli kanaldan ayrılma mesajını metin kanalına gönder
    try {
        const channelDoc = await db.collection('channels').doc(channelId).get();
        const channelName = channelDoc.exists ? channelDoc.data().name : channelId;
        const systemMessage = `${user.nickname}, '${channelName}' sesli kanalından ayrıldı.`;
        // Mesajı ana metin kanalına gönderiyoruz.
        io.to(TEAM_ID).emit('system message', { message: systemMessage, channel: MAIN_CHANNEL });
    } catch (error) { console.error('Sesli kanal ayrılma mesajı gönderilirken hata:', error); }

    getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users)); // Kullanıcı listesini güncelle
  });

  socket.on('toggle status', (data) => {
    const user = onlineUsers[socket.id];
    if (!user) return;
    console.log(`[SUNUCU] ${user.nickname} (${socket.id}) durumu değişti: ${data.status} = ${data.value}`);
    userStatus[socket.id][data.status] = data.value;
    getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users)); // Kullanıcı listesini güncelle
  });

  // 💡 YENİ: Kullanıcı durumunu (presence) güncelleme
  socket.on('status:update', (newStatus) => {
    const user = onlineUsers[socket.id];
    if (!user || !userStatus[socket.id]) return;

    userStatus[socket.id].presence = newStatus;
    console.log(`[SUNUCU] ${user.nickname} durumu güncellendi: ${newStatus}`);
    getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users)); // Herkese güncel listeyi gönder
  });

  socket.on('toggle speaking', (isSpeaking) => { 
    const user = onlineUsers[socket.id];
    if (!user) return;
    console.log(`[SUNUCU] ${user.nickname} (${socket.id}) konuşma durumu: ${isSpeaking}`);
    userStatus[socket.id].speaking = isSpeaking; 
    getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users));
  });
  
  socket.on('typing', (isTyping) => {
    const user = onlineUsers[socket.id];
    if (!user) return;
    socket.to(TEAM_ID).emit('typing', { nickname: user.nickname, isTyping });
  });

  // Kullanıcı ayarlarını getir
  socket.on('user-settings:get', async () => {
    const user = onlineUsers[socket.id];
    if (!user) return;
    try {
      const settingsRef = db.collection('users').doc(user.uid).collection('meta').doc('settings');
      const snap = await settingsRef.get();
      const data = snap.exists ? snap.data() : {};
      socket.emit('user-settings:current', data);
    } catch (err) {
      console.error('Kullanıcı ayarları okunurken hata:', err.message);
      socket.emit('system error', 'Kullanıcı ayarları yüklenemedi.');
    }
  });

  // 💡 YENİ: Kullanıcı ayarlarını kaydet (merge)
  socket.on('user-settings:save', async (payload) => {
    const user = onlineUsers[socket.id];
    if (!user) return;
    try {
      const settingsRef = db.collection('users').doc(user.uid).collection('meta').doc('settings');
      await settingsRef.set(payload || {}, { merge: true });
      socket.emit('user-settings:saved');
    } catch (err) {
      console.error('Kullanıcı ayarları kaydedilirken hata:', err.message);
      socket.emit('system error', 'Kullanıcı ayarları kaydedilemedi.');
    }
  });

  // 💡 YENİ: Kullanıcı engelleme/engel kaldırma
  async function updateUserBlockList(blockerUid, targetUid, shouldBlock) {
    const privacyRef = db.collection('users').doc(blockerUid).collection('meta').doc('privacy');
    try {
      await db.runTransaction(async (transaction) => {
        const privacyDoc = await transaction.get(privacyRef);
        let blocked = [];
        if (privacyDoc.exists) {
          blocked = privacyDoc.data().blocked || [];
        }

        if (shouldBlock) {
          // Eğer zaten engelli değilse ekle
          if (!blocked.includes(targetUid)) {
            blocked.push(targetUid);
          }
        } else {
          // Engeli kaldır
          blocked = blocked.filter(uid => uid !== targetUid);
        }
        transaction.set(privacyRef, { blocked }, { merge: true });
      });

      // Güncel listeyi istemciye geri gönder
      const updatedDoc = await privacyRef.get();
      const updatedBlockedList = updatedDoc.exists ? updatedDoc.data().blocked || [] : [];
      socket.emit('user:blocked_list_update', updatedBlockedList);

    } catch (error) {
      console.error('Engelleme listesi güncellenirken hata:', error);
      socket.emit('system error', 'Engelleme listesi güncellenemedi.');
    }
  }

  socket.on('user:block', ({ targetUid }) => {
    const user = onlineUsers[socket.id];
    if (user && user.uid !== targetUid) updateUserBlockList(user.uid, targetUid, true);
  });
  socket.on('user:unblock', ({ targetUid }) => {
    const user = onlineUsers[socket.id];
    if (user) updateUserBlockList(user.uid, targetUid, false);
  });
  // 💡 YENİ: Sohbet mesajı gönderme ve yanıtlama mantığı
  socket.on('chat message', async ({ msg, channelId, replyTo }) => {
    const user = onlineUsers[socket.id];
    if (!user || !msg.trim()) return;

    let processedMessage = msg;

    // 💡 YENİ: @mention'ları bul ve işle
    const mentionRegex = /@(\w+)/g;
    const allUsers = await getAllUsers(); // Tüm kullanıcıların güncel listesini al
    processedMessage = processedMessage.replace(mentionRegex, (match, mentionedNickname) => {
        const mentionedUser = allUsers.find(u => u.nickname.toLowerCase() === mentionedNickname.toLowerCase());
        if (mentionedUser) {
            // Kullanıcı bulunduysa, özel bir span ile değiştir.
            return `<span class="mention" data-uid="${mentionedUser.uid}">@${mentionedUser.nickname}</span>`;
        }
        // Kullanıcı bulunamadıysa, metni olduğu gibi bırak.
        return match;
    });

    const messageData = {
        senderUid: user.uid,
        senderNickname: user.nickname,
        senderAvatar: user.avatarUrl,
        message: md.renderInline(processedMessage), // 💡 DÜZELTME: İşlenmiş mesajı render et
        channel: channelId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        reactions: {}
    };

    // Eğer bu bir yanıtsa, yanıt bilgilerini ekle
    if (replyTo && replyTo.messageId) {
        messageData.replyTo = {
            messageId: replyTo.messageId,
            messageText: replyTo.messageText,
            senderNickname: replyTo.senderNickname
        };
    }

    try {
        const docRef = await db.collection('messages').add(messageData);
        const savedMessage = { 
            ...messageData, 
            id: docRef.id, 
            timestamp: new Date() // İstemciye hemen göndermek için geçici tarih
        };
        io.to(TEAM_ID).emit('chat message', savedMessage);
    } catch (error) {
        console.error('Mesaj kaydedilirken hata:', error);
    }
  });

  // WebRTC Sinyalleşmesi
  socket.on('offer', (id, message) => { console.log(`[SUNUCU] Offer gönderiliyor to ${id} from ${socket.id}`); socket.to(id).emit('offer', socket.id, message); });
  socket.on('answer', (id, message) => { console.log(`[SUNUCU] Answer gönderiliyor to ${id} from ${socket.id}`); socket.to(id).emit('answer', socket.id, message); });
  socket.on('candidate', (id, message) => { console.log(`[SUNUCU] ICE Candidate gönderiliyor to ${id} from ${socket.id}`); socket.to(id).emit('candidate', socket.id, message); });
  
  // 💡 DÜZELTME: İki tane olan logout dinleyicisi birleştirildi ve token temizleme eklendi.
  socket.on('logout', () => {
    const user = onlineUsers[socket.id];
    if (user) {
        // Kullanıcının tüm token'larını sil
        for (const [token, uid] of autoLoginTokens.entries()) { if (uid === user.uid) { autoLoginTokens.delete(token); } }
        console.log(`[SUNUCU] ${user.nickname} için tüm otomatik giriş token'ları temizlendi.`);
    }
    handleDisconnect(socket.id);
  });

  socket.on('request past messages', (channelId) => {
      sendPastMessages(socket, channelId);
  });

  // Kullanıcı bağlantıyı kestiğinde
  socket.on('disconnect', () => {
    handleDisconnect(socket.id);
  });

  async function handleDisconnect(socketId) {
    console.log(`[SUNUCU] Kullanıcı bağlantısı kesildi: ${socketId}`);
    const user = onlineUsers[socketId];
    if (!user) return;

    // Eğer kullanıcı bir sesli kanaldaysa, ayrılma mesajını metin kanalına gönder
    if (userStatus[socketId] && userStatus[socketId].channel) {
        try {
            const channelDoc = await db.collection('channels').doc(userStatus[socketId].channel).get();
            const channelName = channelDoc.exists ? channelDoc.data().name : userStatus[socketId].channel;
            const systemMessage = `${user.nickname}, '${channelName}' sesli kanalından ayrıldı.`;
            io.to(TEAM_ID).emit('system message', { message: systemMessage, channel: MAIN_CHANNEL });
        } catch (error) { console.error('Sesli kanal bağlantı kopma mesajı gönderilirken hata:', error); }
    } else {
        io.to(TEAM_ID).emit('system message', { message: `${user.nickname} sohbetten ayrıldı.`, channel: MAIN_CHANNEL });
    }
    
    // Eğer sesli kanaldaysa, kanaldan ayrıldığını bildir
    if (userStatus[socketId].channel) {
      socket.to(userStatus[socketId].channel).emit('user left', socketId);
    }

    delete onlineUsers[socketId]; 
    delete userStatus[socketId]; 
    
    getAllUsers().then(users => io.to(TEAM_ID).emit('user list', users));
  }
});

// 💡 DÜZELTME: Sunucuyu başlatma.
server.listen(PORT, () => {
  console.log(`[SUNUCU BAŞARILI] AuraChat port ${PORT}'da çalışıyor.`);
});

// Geçmiş mesajları belirli bir kanaldan çekip gönderen fonksiyon
async function sendPastMessages(socket, channelId) {
    try {
        // 💡 DÜZELTME: Hem genel hem de DM kanalları için mesajlar ana 'messages' koleksiyonunda bulunur.
        // Bu yüzden koşullu mantığı kaldırıp her zaman aynı yerden çekiyoruz.
        const messagesRef = db.collection('messages')
                            .where('channel', '==', channelId)
                            .orderBy('timestamp', 'desc')
                            .limit(50);
        const snapshot = await messagesRef.get();
        const pastMessages = [];
        snapshot.forEach(doc => {
            const data = doc.data();
            pastMessages.unshift({ ...data, timestamp: data.timestamp.toDate(), id: doc.id }); // En eski mesaj en üstte olacak şekilde sırala
        });
        socket.emit('past messages', { channelId, messages: pastMessages });
    } catch (error) {
        console.error('Geçmiş mesajları çekerken hata:', error);
    }
}

// Tüm kanalları veritabanından çekip gönderen fonksiyon
async function sendChannelList(socket) {
    try {
        const channelsSnapshot = await db.collection('channels').get();
        const channels = [];
        channelsSnapshot.forEach(doc => {
            channels.push({ id: doc.id, ...doc.data() });
        });
        // İstemciye sadece istek atan kullanıcıya gönder
        socket.emit('channel-list', channels);
    } catch (error) {
        console.error('Kanal listesi çekerken hata:', error);
    }
}

// 💡 DÜZELTME: Kullanıcının dahil olduğu tüm DM kanallarını ve diğer katılımcı bilgilerini getiren fonksiyon
async function sendDmHistory(socket, userId) {
  try {
    if (!userId) return console.error('[SUNUCU] sendDmHistory: userId eksik.');

    const dmChannelsSnapshot = await db.collection('dm-channels')
                                        .where('participants', 'array-contains', userId)
                                        .get();
    const dmChannelInfos = [];
    for (const doc of dmChannelsSnapshot.docs) {
        const channelId = doc.id;
        const participants = doc.data().participants;
        const otherUserUid = participants.find(uid => uid !== userId);
        
        if (otherUserUid) {
            const otherUserDoc = await db.collection('users').doc(otherUserUid).get();
            if (otherUserDoc.exists) {
                const otherUserData = otherUserDoc.data();
                dmChannelInfos.push({ id: channelId, nickname: otherUserData.nickname, avatarUrl: otherUserData.avatarUrl, uid: otherUserUid });
            }
        }
    }
    socket.emit('dm history', dmChannelInfos);
    console.log(`[SUNUCU] DM kanalları gönderildi: ${userId} -> ${dmChannelInfos.length} kanal`);
  } catch (error) {
    console.error('DM geçmişi çekerken hata:', error);
  }
}
