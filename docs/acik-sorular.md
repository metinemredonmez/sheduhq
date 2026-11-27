# Açık sorular

Mimariyi ve takvimi doğrudan etkileyen, henüz yanıtı olmayan sorular.

| # | Soru | Neyi etkiler? |
|---|---|---|
| 1 | Hedef alarm panelleri hangi markalar ve sunucuya hangi protokolle bağlanıyor (MQTT, özel TCP, SIA DC-09, Contact ID)? | Gateway tasarımı, takvimin en büyük belirsizliği |
| 2 | Kendi alarm izleme merkezimiz olacak mı, yoksa mevcut bir izleme merkezi yazılımıyla mı entegre olacağız? | Operatör konsolunun kapsamı ve fazı |
| 3 | Satış modeli: doğrudan son kullanıcıya mı, izleme firmalarına beyaz etiketli platform olarak mı? | Çok kiracılı yapı, marka özelleştirme |
| 4 | Kamera sağlayıcıları canlı yayını HLS veya WebRTC olarak sunuyor mu? | Mobilde video oynatma, yayın aktarıcısı ihtiyacı |
| 5 | Veriler nerede barındırılacak? Yurt dışındaki bir LLM sağlayıcısına veri aktarımı için KVKK dayanağı ne? | Altyapı, AI özelliklerinin kapsamı |
| 6 | "Shedu" marka tescili (sınıf 9, 42, 45) ve alan adları | Ürün adı, paket kimlikleri (bundle id) |
| 7 | iOS kritik bildirim (critical alerts) izni için Apple başvurusu | Sessiz moddayken alarm bildirimi |
| 8 | KVKK'da veri sorumlusu kim: son kullanıcıya hizmet veren izleme firması mı, Shedu mu (veri işleyen)? | Aydınlatma metni, VERBİS kaydı, sözleşmeler, başvuruların kime yapılacağı |
| 9 | Aydınlatma metnini kim yazacak ve uygulamada nerede gösterilecek (kayıt, ayarlar)? | Kayıt akışı, mobil ve web ekranları |
| 10 | Saklama süreleri ne olacak: komut ve olay geçmişi, denetim kaydı, bildirim teslim kayıtları? Hesap silindikten sonra güvenlik kayıtları ne kadar tutulacak? | Otomatik silme işi, silme akışının kapsamı |
| 11 | Push bildirimleri FCM (Google) ve APNs (Apple) üzerinden yurt dışına çıkıyor: KVKK md. 9 kapsamında aktarım dayanağı ne (standart sözleşme, açık rıza)? Bildirim içeriğinde hangi bilgi yer alabilir? | Push metinleri, sağlayıcı seçimi, rıza ekranı |
| 12 | Hangi işlemler için açık rıza gerekiyor (ör. pazarlama bildirimleri, AI özellikleri, kamera görüntüsü), hangileri sözleşmenin ifası veya meşru menfaate dayanıyor? | Rıza kayıtları, ayarlar ekranı, AI servisi |
