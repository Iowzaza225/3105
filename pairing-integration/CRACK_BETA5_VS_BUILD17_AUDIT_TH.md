# 3105 Beta 5 Crack IPA vs RUIZEN Build 17 — ตรวจเทียบเส้นทางจริง

ตรวจจากไฟล์ IPA ที่ผู้ใช้ส่งมา `3105 Beta 5 Crack (2).ipa` (ไม่ใช่ซอร์สโค้ด)
อ้างอิงโค้ด RUIZEN บน `feature/ruizen-build17-airlift-apply-route`.

## สิ่งที่ยืนยันได้จาก IPA

- `Info.plist`: ชื่อ 3105, version 2.1, build 12, identifier `com.apple.mobile.MobileHouseArrest`, SDK 26.2.
- มีข้อความ/ฟังก์ชันเกี่ยวกับ RPPairing, TLS-PSK, CDTunnel, RSD และ RSD service discovery.
- มีข้อความ `airlift.tunnel … strategy=aircard_multihost`; แสดงว่าตัวอ้างอิงมีทางเลือก multi-host และ fallback ไป classic Lockdown.
- พบบริการ `com.apple.atc.shim.remote`, โพรบ Streaming ZIP, การเริ่ม sync, ตรวจ `SyncAllowed`/`AssetManifest` และยืนยันผลการถ่ายโอน.
- มีข้อความเกี่ยวกับ AFC/Media staging, จัดเตรียมและคืนค่าไฟล์, SHA-256 และกรณีที่ cleanup ไม่สมบูรณ์.
- มีคำเรียก CoreDevice FileService สำหรับอ่าน/แสดงรายการไฟล์.
- ใน THIRD_PARTY_NOTICES.md ระบุ AirCard-iOS strategy บน commit `40640c4d827aeab8d798285b57d24fcf6be070d0` และ idevice commit `3854a5df4a5a6dee71ffce4d8befc2ea356a8065`.

**ข้อจำกัดหลักฐาน:** สตริงและฟังก์ชันบอกว่ามีการติดตั้ง logic ไว้ ไม่ใช่การพิสูจน์ว่าทุกเส้นทางทำงานกับทุกแอปได้จริง หรือพิสูจน์ว่าแต่ละ patch ในเครื่องใช้ route ใด.

## ความแตกต่างสำคัญกับ RUIZEN Build17

| ระบบ | Crack Beta5 | RUIZEN Build17 |
| --- | --- | --- |
| ตรวจ iOS 27.0.1 (24A446) | แสดง Supported ตามภาพจากผู้ใช้ | ตั้งค่ารองรับ AirLift iOS 27.0.1 |
| Pairing, TLS-PSK, CDTunnel, RSD | พบใน IPA | ผ่านผลทดสอบจริง Build 16 |
| AFC ขนาดเล็ก | มี | ทดสอบ write+readback ผ่านจริงใน PublicStaging |
| Multi-host route & Lockdown fallback | พบใน IPA | ยังไม่มี route เทียบเท่าครบ |
| ATC sync / Streaming ZIP | พบใน IPA | **ยังไม่ได้เชื่อม** |
| CoreDevice FileService / ATC scopes | พบใน IPA | **ยังไม่ได้เชื่อม** |
| Apply Patch | มีหลายกลไกและขั้นยืนยันผล | Build17 ใช้ HouseArrest/VendDocuments ซึ่งจำกัดสิทธิ์ |

**ห้ามเรียก Build17 ว่า copy exact method จาก Crack**; ใช้ได้เฉพาะสิทธิ์ที่ HouseArrest อนุญาตตามจริง

## ทางดำเนินงานที่ถูกต้อง

1. คงระบบ Pair-Verify, CDTunnel, RSD ที่พิสูจน์ผ่านแล้ว ไม่ทำซ้ำอีก.
2. แยกสถานะ `OS supported`, `Tunnel connected`, `service available`, `destination writable` และ `patch verified` ห้ามให้ข้อความ Supported แทนผลทุกขั้น.
3. ฝังการเลือก transport ตามขอบเขตที่อนุญาต: AFC staging, HouseArrest Documents, CoreDevice FileService เมื่อมีสิทธิ์; ตรวจสิทธิ์และอ่านกลับทุกครั้ง.
4. สำหรับเส้นทาง ATC/Streaming ZIP ที่ยังไม่มีซอร์ส Beta5 ต้องใช้ซอร์สที่มีสิทธิ์ใช้งานหรือพัฒนาใหม่และทดสอบอย่างเป็นขั้นตอน; อย่าแสร้งว่า source 3105 2.0 ที่เปิดสาธารณะคือ Beta5.
5. ห้ามนำ IPA ที่คอมไพล์แล้วมาปะปนเป็น Swift source; ต้องทำการพอร์ต API/behavior โดยรักษา attribution และเงื่อนไข license ที่เกี่ยวข้อง.
6. ถ้าการเข้าถึงต้องอาศัย bypass ขอบเขตความปลอดภัยของแอปอื่น ต้องแยกออกจากการรองรับ iOS 27.0.1 ตามปกติ ไม่อ้างว่าการผ่าน RSD เท่ากับมีสิทธิ์เขียนทุกโฟลเดอร์.

สถานะ: **Crack IPA inspected, gap classified. ไม่มีการรับรองว่า ATC/Streaming ZIP port พร้อมใช้งานใน Build17**.
