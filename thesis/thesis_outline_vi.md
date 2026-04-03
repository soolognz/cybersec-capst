# DE CUONG LUAN VAN TOT NGHIEP
# (Thesis Outline / Capstone Project Report)

**Truong Dai hoc FPT (FPT University)**
**Nganh: Dam bao An toan Thong tin (Information Assurance)**

---

**De tai / Title:**
**"Ung dung AI trong phat hien va phong chong tan cong Brute-force tren he thong SSH voi du doan som"**
*(Application of AI in Detecting and Preventing Brute-Force Attacks on SSH Systems with Early Prediction)*

---

**Tong so trang du kien: 90-100 trang**
**So chuong: 6 chuong chinh + Phu luc**

---

## MUC LUC TONG QUAT (Table of Contents Overview)

| Phan                          | So trang du kien |
|-------------------------------|:----------------:|
| Trang bia + Loi cam on + Tom tat | 5              |
| Muc luc + Danh muc           | 4                |
| Chuong 1: Mo dau             | 8-10             |
| Chuong 2: Co so ly thuyet    | 18-22            |
| Chuong 3: Phan tich & Thiet ke | 14-16          |
| Chuong 4: Hien thuc          | 16-18            |
| Chuong 5: Ket qua & Danh gia | 14-16           |
| Chuong 6: Ket luan           | 5-6              |
| Tai lieu tham khao            | 3-4              |
| Phu luc                      | 5-8              |
| **Tong cong**                 | **92-109**       |

---

## PHAN MO DAU (Preliminary Pages) -- 9 trang

### Trang bia (Cover Page) -- 1 trang
- Logo FPT University
- Ten de tai (Tieng Viet va Tieng Anh)
- Ho ten sinh vien, MSSV
- Giang vien huong dan
- Ky hoc, nam hoc

### Loi cam on (Acknowledgments) -- 1 trang

### Tom tat luan van (Abstract) -- 2 trang
- Tom tat tieng Viet (1 trang)
- Tom tat tieng Anh (1 trang)
- **Noi dung:** Van de nghien cuu, phuong phap, ket qua chinh (IF F1=0.886, Recall=99.99%), dong gop

### Danh muc (Lists) -- 4 trang
- Muc luc (Table of Contents)
- Danh muc hinh anh (List of Figures) -- du kien 25-35 hinh
- Danh muc bang bieu (List of Tables) -- du kien 15-20 bang
- Danh muc tu viet tat (List of Abbreviations): SSH, AI, IF, LOF, OCSVM, EWMA, ELK, ROC, AUC, FPR, TPR, HIDS, NIDS, IDS, IPS, API...
- Danh muc ky hieu (List of Symbols -- neu co)

### Loi mo dau / Gioi thieu (Preface) -- 1 trang

---

## CHUONG 1: MO DAU (Introduction) -- 8-10 trang

### 1.1. Dat van de (Problem Statement) -- 2 trang
**Noi dung chinh:**
- Thuc trang an ninh mang hien nay: so lieu thong ke tan cong brute-force toan cau
- SSH la giao thuc quan trong nhung thuong xuyen bi khai thac
- Han che cua cac phuong phap phong chong truyen thong (rule-based, signature-based)
- Nhu cau ung dung AI/ML de phat hien som va tu dong

**Luan diem:**
- Theo bao cao Verizon DBIR 2024, tan cong brute-force chiem ~25% cac vu vi pham
- Cac he thong rule-based nhu Fail2Ban mac dinh chi phan ung sau khi tan cong da xay ra, khong co kha nang du doan
- Gap thoi gian giua phat hien va phan ung la diem yeu cot loi

**Trich dan de xuat:**
- [1] Verizon. (2024). *Data Breach Investigations Report (DBIR)*. Truy cap: https://www.verizon.com/business/resources/reports/dbir/
- [2] Helmiawan, M. A., et al. (2020). "Brute Force Attack on SSH Port." *IOP Conference Series*, doi:10.1088/1742-6596/1477/3/032014
- [3] Nguyen Van A., Tran Van B. (2022). "Thuc trang an ninh mang tai Viet Nam va giai phap." *Tap chi Khoa hoc Cong nghe Thong tin va Truyen thong*, Bo TTTT.

**Hinh/Bang de xuat:**
- Hinh 1.1: Bieu do thong ke tan cong brute-force SSH toan cau 2020-2025 (tu Shodan/Honeypot data)
- Hinh 1.2: So sanh timeline phat hien cua rule-based vs AI-based
- Bang 1.1: So sanh cac phuong phap phong chong brute-force hien tai

---

### 1.2. Muc tieu nghien cuu (Research Objectives) -- 1 trang
**Muc tieu tong quat:**
- Xay dung he thong phat hien va phong chong tan cong brute-force SSH su dung AI voi kha nang du doan som

**Muc tieu cu the:**
1. Trich xuat 14 dac trung hanh vi tu SSH log theo cua so 5 phut
2. Huan luyen mo hinh Isolation Forest phat hien bat thuong (semi-supervised)
3. Thiet ke nguong dong EWMA-Adaptive Percentile cho du doan som
4. Tich hop Fail2Ban de tu dong chan IP bat thuong
5. Xay dung dashboard giam sat bang ELK Stack + Kibana
6. Docker hoa toan bo he thong
7. Danh gia hieu suat voi 5 kich ban tan cong mo phong

**Hinh/Bang de xuat:**
- Hinh 1.3: So do muc tieu nghien cuu (mind map)

---

### 1.3. Doi tuong va pham vi nghien cuu (Scope and Limitations) -- 1 trang
**Doi tuong:**
- He thong SSH server (OpenSSH)
- Tan cong brute-force (password guessing, credential stuffing, dictionary attack)
- Cac mo hinh hoc khong giam sat (Unsupervised/Semi-supervised Anomaly Detection)

**Pham vi:**
- Chi tap trung vao tan cong brute-force (khong bao gom DDoS, exploit, etc.)
- Moi truong lab mo phong (Docker containers)
- Du lieu: SSH authentication logs (auth.log)
- 14 dac trung tinh theo cua so 5 phut

**Gioi han:**
- Khong thu nghiem tren moi truong production thuc te
- Khong bao gom key-based authentication attacks
- Du lieu mo phong, chua co du lieu thuc tu doanh nghiep

---

### 1.4. Phuong phap nghien cuu (Research Methodology) -- 2 trang
**Noi dung chinh:**
1. **Nghien cuu ly thuyet:** Tong hop tai lieu ve anomaly detection, SSH security
2. **Thiet ke thuc nghiem:** Xay dung moi truong lab, thu thap du lieu
3. **Phat trien mo hinh:** Feature engineering, model training, threshold tuning
4. **Danh gia:** So sanh IF vs LOF vs OCSVM, 5 kich ban tan cong
5. **Phan tich ket qua:** Thong ke, truc quan hoa, kiem dinh

**Luan diem:**
- Su dung phuong phap semi-supervised: chi hoc tu du lieu binh thuong (7,212 mau) de phat hien bat thuong
- Ly do chon semi-supervised: trong thuc te, du lieu tan cong kho thu thap va da dang, du lieu binh thuong de co hon

**Trich dan de xuat:**
- [4] Chandola, V., Banerjee, A., & Kumar, V. (2009). "Anomaly detection: A survey." *ACM Computing Surveys*, 41(3), 1-58. doi:10.1145/1541880.1541882
- [5] Goldstein, M., & Uchida, S. (2016). "A comparative evaluation of unsupervised anomaly detection algorithms for multivariate data." *PLoS ONE*, 11(4), e0152173.

**Hinh/Bang de xuat:**
- Hinh 1.4: So do quy trinh nghien cuu (Research workflow diagram)
- Hinh 1.5: Timeline thuc hien de tai (Gantt chart)

---

### 1.5. Y nghia khoa hoc va thuc tien (Significance) -- 1 trang
**Y nghia khoa hoc:**
- Dong gop phuong phap ket hop EWMA-Adaptive Percentile cho du doan som tan cong
- So sanh he thong ba mo hinh anomaly detection trong boi canh SSH security
- De xuat bo 14 dac trung hieu qua cho SSH brute-force detection

**Y nghia thuc tien:**
- He thong co the trien khai thuc te tai cac doanh nghiep vua va nho
- Giam thoi gian phat hien tu "sau tan cong" xuong "trong khi tan cong"
- Tich hop voi Fail2Ban -- cong cu phong chong pho bien nhat

---

### 1.6. Bo cuc luan van (Thesis Structure) -- 1 trang
- Mo ta ngan gon noi dung 6 chuong

---

## CHUONG 2: CO SO LY THUYET VA CONG NGHE (Theoretical Background & Technology) -- 18-22 trang

### 2.1. Tong quan ve tan cong Brute-force (Overview of Brute-Force Attacks) -- 3 trang

#### 2.1.1. Khai niem va phan loai (Definition and Classification) -- 1 trang
**Noi dung chinh:**
- Dinh nghia brute-force attack
- Phan loai: Simple brute-force, Dictionary attack, Credential stuffing, Hybrid attack, Reverse brute-force
- Quy trinh tan cong dien hinh

**Trich dan de xuat:**
- [6] Owens, J., & Matthews, J. (2020). "A Study of Passwords and Methods Used in Brute-Force SSH Attacks." *USENIX Workshop on Large-Scale Exploits and Emergent Threats (LEET)*.
- [7] OWASP Foundation. (2023). *Brute Force Attack*. https://owasp.org/www-community/attacks/Brute_force_attack

**Hinh/Bang de xuat:**
- Hinh 2.1: So do quy trinh tan cong brute-force SSH
- Bang 2.1: Phan loai cac kieu tan cong brute-force

#### 2.1.2. Tan cong Brute-force tren SSH (SSH Brute-Force Attacks) -- 1 trang
**Noi dung chinh:**
- Giao thuc SSH va co che xac thuc (password, key-based, multi-factor)
- Tai sao SSH la muc tieu hap dan (port 22, remote access, pho bien tren server)
- Cac cong cu tan cong: Hydra, Medusa, Ncrack, Patator
- Dau hieu nhan biet trong log: Failed password, Invalid user, Connection closed

**Trich dan de xuat:**
- [8] Ylonen, T., & Lonvick, C. (2006). *The Secure Shell (SSH) Protocol Architecture*. RFC 4251, IETF.
- [9] Najafabadi, M. M., et al. (2015). "Deep learning applications and challenges in big data analytics." *Journal of Big Data*, 2(1), 1-21.

**Hinh/Bang de xuat:**
- Hinh 2.2: Kien truc giao thuc SSH
- Hinh 2.3: Vi du log SSH khi bi tan cong brute-force

#### 2.1.3. Cac phuong phap phong chong truyen thong (Traditional Prevention Methods) -- 1 trang
**Noi dung chinh:**
- Rate limiting, IP blacklisting
- Fail2Ban, DenyHosts, SSHGuard
- Port knocking, thay doi port
- Key-based authentication
- Han che: deu la reactive, khong predictive

**Trich dan de xuat:**
- [10] Shirali-Shahreza, S., & Ganjali, Y. (2015). "Efficient implementation of security applications in OpenFlow controller with FleXam." *IEEE HPSR*, pp. 49-54.

**Hinh/Bang de xuat:**
- Bang 2.2: So sanh cac phuong phap phong chong truyen thong (uu/nhuoc diem)

---

### 2.2. Phat hien bat thuong bang Machine Learning (Anomaly Detection with ML) -- 5 trang

#### 2.2.1. Tong quan ve Anomaly Detection (Overview) -- 1.5 trang
**Noi dung chinh:**
- Dinh nghia anomaly/outlier
- Ba phuong phap chinh: supervised, semi-supervised, unsupervised
- Tai sao chon semi-supervised cho bai toan nay
- Cac ung dung trong an ninh mang

**Trich dan de xuat:**
- [4] Chandola, V., Banerjee, A., & Kumar, V. (2009). "Anomaly detection: A survey." *ACM Computing Surveys*, 41(3), 1-58.
- [11] Pang, G., Shen, C., Cao, L., & Hengel, A. V. D. (2021). "Deep learning for anomaly detection: A review." *ACM Computing Surveys*, 54(2), 1-38. doi:10.1145/3439950
- [12] Chalapathy, R., & Chawla, S. (2019). "Deep learning for anomaly detection: A survey." *arXiv preprint arXiv:1901.03407*.

**Hinh/Bang de xuat:**
- Hinh 2.4: Phan loai cac phuong phap anomaly detection
- Hinh 2.5: So sanh supervised vs semi-supervised vs unsupervised

#### 2.2.2. Isolation Forest (IF) -- Mo hinh chinh -- 1.5 trang
**Noi dung chinh:**
- Nguyen ly hoat dong: co lap diem bat thuong bang cay quyet dinh ngau nhien
- Thuat toan: xay dung iTree, tinh anomaly score
- Cong thuc anomaly score: s(x, n) = 2^(-E(h(x))/c(n))
- Do phuc tap: O(t * n * log(psi)) voi t = so cay, psi = sub-sampling size
- Uu diem: hieu qua voi du lieu cao chieu, khong can gia dinh phan phoi, nhanh
- Nhuoc diem: co the kem voi du lieu co nhieu dac trung khong lien quan

**Trich dan de xuat:**
- [13] Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). "Isolation Forest." *Proc. IEEE ICDM*, pp. 413-422. doi:10.1109/ICDM.2008.17
- [14] Liu, F. T., Ting, K. M., & Zhou, Z. H. (2012). "Isolation-based anomaly detection." *ACM Transactions on Knowledge Discovery from Data*, 6(1), 1-39.
- [15] Hariri, S., Kind, M. C., & Brunner, R. J. (2021). "Extended isolation forest." *IEEE Transactions on Knowledge and Data Engineering*, 33(4), 1479-1489.

**Hinh/Bang de xuat:**
- Hinh 2.6: Minh hoa nguyen ly Isolation Forest (diem binh thuong vs bat thuong)
- Hinh 2.7: Quy trinh xay dung iTree va tinh anomaly score
- Bang 2.3: Cac sieu tham so cua Isolation Forest

#### 2.2.3. Local Outlier Factor (LOF) -- Mo hinh doi chung -- 0.75 trang
**Noi dung chinh:**
- Nguyen ly: do mat do cuc bo (local density) bang k-nearest neighbors
- LOF score: ti le mat do cuc bo cua diem so voi cac lan can
- Uu diem: phat hien tot cac diem bat thuong cuc bo
- Nhuoc diem: cham voi du lieu lon, nhay cam voi k

**Trich dan de xuat:**
- [16] Breunig, M. M., Kriegel, H. P., Ng, R. T., & Sander, J. (2000). "LOF: Identifying density-based local outliers." *Proc. ACM SIGMOD*, pp. 93-104.

**Hinh/Bang de xuat:**
- Hinh 2.8: Minh hoa LOF -- mat do cuc bo va diem bat thuong

#### 2.2.4. One-Class SVM (OCSVM) -- Mo hinh doi chung -- 0.75 trang
**Noi dung chinh:**
- Nguyen ly: tim sieu phang tach du lieu binh thuong khoi goc toa do trong khong gian dac trung
- Kernel trick: RBF kernel
- Uu diem: co so ly thuyet vung chac (Vapnik)
- Nhuoc diem: O(n^2) - O(n^3), nhay cam voi tham so nu va gamma

**Trich dan de xuat:**
- [17] Scholkopf, B., Platt, J. C., Shawe-Taylor, J., Smola, A. J., & Williamson, R. C. (2001). "Estimating the support of a high-dimensional distribution." *Neural Computation*, 13(7), 1443-1471.
- [18] Tax, D. M., & Duin, R. P. (2004). "Support vector data description." *Machine Learning*, 54(1), 45-66.

**Hinh/Bang de xuat:**
- Hinh 2.9: Minh hoa One-Class SVM voi RBF kernel

#### 2.2.5. So sanh ba mo hinh (Comparison of Three Models) -- 0.5 trang
**Hinh/Bang de xuat:**
- Bang 2.4: So sanh IF vs LOF vs OCSVM (do phuc tap, uu/nhuoc diem, ung dung)

---

### 2.3. Ky thuat nguong dong va du doan som (Dynamic Thresholding & Early Prediction) -- 3 trang

#### 2.3.1. EWMA (Exponentially Weighted Moving Average) -- 1 trang
**Noi dung chinh:**
- Cong thuc: z_t = lambda * x_t + (1 - lambda) * z_{t-1}
- Y nghia: cho trong so cao hon voi du lieu gan day
- Ung dung trong phat hien thay doi (change detection) trong chuoi thoi gian
- Lien he voi control chart trong SPC (Statistical Process Control)

**Trich dan de xuat:**
- [19] Roberts, S. W. (1959). "Control chart tests based on geometric moving averages." *Technometrics*, 1(3), 239-250.
- [20] Lucas, J. M., & Saccucci, M. S. (1990). "Exponentially weighted moving average control schemes." *Technometrics*, 32(1), 1-12.

**Hinh/Bang de xuat:**
- Hinh 2.10: Minh hoa EWMA voi cac gia tri lambda khac nhau
- Hinh 2.11: EWMA control chart

#### 2.3.2. Adaptive Percentile Threshold -- 1 trang
**Noi dung chinh:**
- Nguyen ly: dieu chinh nguong phat hien dua tren phan vi (percentile) cua diem bat thuong
- Cach tinh: nguong = percentile(anomaly_scores, q) voi q thay doi theo tinh hinh
- Ket hop voi EWMA: EWMA lam min diem, Adaptive Percentile xac dinh nguong dong
- Loi the so voi nguong co dinh: tu dieu chinh theo phan phoi du lieu thay doi

**Trich dan de xuat:**
- [21] Siffer, A., Fouque, P. A., Termier, A., & Largouet, C. (2017). "Anomaly detection in streams with extreme value theory." *Proc. ACM SIGKDD*, pp. 1067-1075.
- [22] Ahmad, S., Lavin, A., Purdy, S., & Agha, Z. (2017). "Unsupervised real-time anomaly detection for streaming data." *Neurocomputing*, 262, 134-147.

**Hinh/Bang de xuat:**
- Hinh 2.12: So do ket hop EWMA + Adaptive Percentile
- Hinh 2.13: So sanh nguong co dinh vs nguong dong tren du lieu thuc te

#### 2.3.3. Co che du doan som (Early Prediction Mechanism) -- 1 trang
**Noi dung chinh:**
- Dinh nghia "du doan som": phat hien y dinh tan cong truoc khi hoan thanh
- Cua so truot 5 phut: tai sao chon 5 phut (can bang giua do tre va do chinh xac)
- Pipeline: Log -> Feature extraction -> Anomaly score -> EWMA smoothing -> Adaptive threshold -> Alert/Ban
- So sanh voi phuong phap Fail2Ban mac dinh (chi dem so lan that bai)

**Hinh/Bang de xuat:**
- Hinh 2.14: Timeline so sanh: phat hien truyen thong vs du doan som
- Bang 2.5: Cac muc canh bao (warning, alert, critical) va hanh dong tuong ung

---

### 2.4. Cong nghe va cong cu su dung (Technologies and Tools) -- 4 trang

#### 2.4.1. ELK Stack (Elasticsearch, Logstash, Kibana) -- 1.5 trang
**Noi dung chinh:**
- Kien truc ELK Stack
- Elasticsearch: luu tru va tim kiem log
- Logstash: thu thap va xu ly log (pipeline: input -> filter -> output)
- Kibana: truc quan hoa va dashboard
- Tai sao chon ELK: open-source, scalable, ecosystem lon

**Trich dan de xuat:**
- [23] Gormley, C., & Tong, Z. (2015). *Elasticsearch: The Definitive Guide*. O'Reilly Media.
- [24] Bajer, M. (2017). "Building an IoT data hub with Elasticsearch, Logstash and Kibana." *IEEE FiCloudW*, pp. 63-68.

**Hinh/Bang de xuat:**
- Hinh 2.15: Kien truc ELK Stack trong he thong
- Hinh 2.16: Pipeline xu ly log voi Logstash

#### 2.4.2. Fail2Ban -- 0.5 trang
**Noi dung chinh:**
- Kien truc va co che hoat dong (log monitoring -> filter -> action)
- Cau hinh jail cho SSH
- Tich hop voi he thong AI: API custom action

**Trich dan de xuat:**
- [25] Fail2Ban Documentation. https://www.fail2ban.org/

**Hinh/Bang de xuat:**
- Hinh 2.17: Luong xu ly cua Fail2Ban

#### 2.4.3. Docker va Container hoa (Docker & Containerization) -- 1 trang
**Noi dung chinh:**
- Khai niem container hoa
- Docker Compose: orchestration nhieu container
- Loi ich: moi truong nhat quan, de trien khai, co lap
- Cac container trong he thong: SSH server, ELK, AI engine, Fail2Ban

**Trich dan de xuat:**
- [26] Merkel, D. (2014). "Docker: Lightweight Linux containers for consistent development and deployment." *Linux Journal*, 2014(239), 2.

**Hinh/Bang de xuat:**
- Hinh 2.18: Kien truc Docker cua he thong (docker-compose topology)
- Bang 2.6: Danh sach cac Docker container va chuc nang

#### 2.4.4. Python va thu vien ML (Python & ML Libraries) -- 1 trang
**Noi dung chinh:**
- Python 3.x: ngon ngu chinh
- scikit-learn: Isolation Forest, LOF, One-Class SVM
- pandas, numpy: xu ly du lieu
- matplotlib, seaborn: truc quan hoa
- Cac thu vien khac: paramiko, elasticsearch-py

**Hinh/Bang de xuat:**
- Bang 2.7: Danh sach thu vien va phien ban su dung

---

### 2.5. Cac nghien cuu lien quan (Related Work) -- 4 trang

#### 2.5.1. Nghien cuu quoc te (International Research) -- 2.5 trang
**Noi dung chinh:**
- Tong hop cac nghien cuu ve SSH brute-force detection bang ML (2015-2025)
- Phan tich uu/nhuoc diem cua tung nghien cuu
- Xac dinh gap nghien cuu (research gap)

**Trich dan de xuat:**
- [27] Hofstede, R., Celeda, P., Trammell, B., Drago, I., Sadre, R., Sperotto, A., & Pras, A. (2014). "Flow monitoring explained: From packet capture to data analysis with NetFlow and IPFIX." *IEEE Communications Surveys & Tutorials*, 16(4), 2037-2064.
- [28] Sperotto, A., Schaffrath, G., Sadre, R., Morariu, C., Pras, A., & Stiller, B. (2010). "An overview of IP flow-based intrusion detection." *IEEE Communications Surveys & Tutorials*, 12(3), 343-356.
- [29] Kumari, P., & Jain, A. (2023). "A comprehensive study of DDoS attacks over IoT network and their countermeasures." *Computers & Security*, 127, 103096.
- [30] Ring, M., Wunderlich, S., Scheuring, D., Landes, D., & Hotho, A. (2019). "A survey of network-based intrusion detection data sets." *Computers & Security*, 86, 147-167.
- [31] Aminanto, M. E., & Kim, K. (2016). "Detecting impersonation attack in WiFi networks using deep learning approach." *ICTC 2016*, pp. 136-141.
- [32] Bezerra, V. H., da Costa, V. G. T., Barbon Junior, S., Miani, R. S., & Zarpelao, B. B. (2019). "IoTDS: A one-class classification approach to detect botnets in IoT." *Sensors*, 19(14), 3188.
- [33] Alhajjar, E., Maxwell, P., & Bastian, N. (2021). "Adversarial machine learning in Network Intrusion Detection Systems." *Expert Systems with Applications*, 186, 115782.
- [34] Sarker, I. H. (2021). "Machine learning: Algorithms, real-world applications and research directions." *SN Computer Science*, 2(3), 160.
- [35] Buczak, A. L., & Guven, E. (2016). "A survey of data mining and machine learning methods for cyber security intrusion detection." *IEEE Communications Surveys & Tutorials*, 18(2), 1153-1176.
- [36] Idhammad, M., Afdel, K., & Belouch, M. (2018). "Semi-supervised machine learning approach for DDoS detection." *Applied Intelligence*, 48(10), 3713-3726.
- [37] Ahmed, M., Mahmood, A. N., & Hu, J. (2016). "A survey of network anomaly detection techniques." *Journal of Network and Computer Applications*, 60, 19-31.

**Hinh/Bang de xuat:**
- Bang 2.8: Tong hop cac nghien cuu quoc te lien quan (tac gia, nam, phuong phap, ket qua, han che)

#### 2.5.2. Nghien cuu trong nuoc (Vietnamese Research) -- 1 trang
**Noi dung chinh:**
- Cac nghien cuu ve an ninh mang va ung dung AI tai Viet Nam
- Cac luan van, bai bao tai cac truong dai hoc Viet Nam

**Trich dan de xuat:**
- [38] Nguyen Huy Trung, Nguyen Minh Hai. (2021). "Ung dung hoc may trong phat hien xam nhap mang." *Tap chi Khoa hoc va Cong nghe - Dai hoc Da Nang*, so 19(5), pp. 45-52.
- [39] Le Hai Viet, Pham Van Hau. (2022). "Nghien cuu va ung dung mo hinh Isolation Forest trong phat hien tan cong mang." *Ky yeu Hoi thao KHCN Quoc gia ve ATTT*, VNISA.
- [40] Tran Minh Triet, Nguyen Thanh Son. (2020). "Phat hien bat thuong trong luu luong mang su dung ket hop hoc sau va hoc may truyen thong." *Tap chi Phat trien KH&CN - DHQG TP.HCM*, 4(2), pp. 580-592.
- [41] Vu Thanh Nguyen et al. (2023). "SSH intrusion detection using ensemble learning on system logs." *Journal of Science and Technology on Information Security (VNISA)*, 2(18), pp. 33-41.

**Hinh/Bang de xuat:**
- Bang 2.9: Tong hop cac nghien cuu trong nuoc lien quan

#### 2.5.3. Khoang trong nghien cuu va dong gop (Research Gap & Contribution) -- 0.5 trang
**Noi dung chinh:**
- Hau het nghien cuu hien tai: supervised, can du lieu gan nhan (labeled data)
- It nghien cuu ket hop anomaly detection voi dynamic threshold cho du doan som
- It he thong tich hop end-to-end (detection + prevention + monitoring)
- Dong gop cua luan van:
  1. Bo 14 dac trung chuyen biet cho SSH brute-force
  2. Nguong dong EWMA-Adaptive Percentile
  3. He thong tich hop end-to-end voi Docker

**Hinh/Bang de xuat:**
- Bang 2.10: Research gap analysis (van de -- nghien cuu hien tai -- dong gop cua luan van)

---

## CHUONG 3: PHAN TICH VA THIET KE HE THONG (System Analysis & Design) -- 14-16 trang

### 3.1. Yeu cau he thong (System Requirements) -- 2 trang

#### 3.1.1. Yeu cau chuc nang (Functional Requirements) -- 1 trang
**Noi dung chinh:**
- FR1: Thu thap va xu ly SSH log tu nhieu nguon
- FR2: Trich xuat 14 dac trung tu log theo cua so 5 phut
- FR3: Tinh diem bat thuong (anomaly score) bang mo hinh AI
- FR4: Ap dung nguong dong EWMA-Adaptive Percentile
- FR5: Gui canh bao khi phat hien bat thuong
- FR6: Tu dong chan IP qua Fail2Ban
- FR7: Hien thi dashboard giam sat thoi gian thuc tren Kibana
- FR8: Luu tru lich su canh bao va hanh dong

**Hinh/Bang de xuat:**
- Bang 3.1: Danh sach yeu cau chuc nang (ID, mo ta, do uu tien)

#### 3.1.2. Yeu cau phi chuc nang (Non-Functional Requirements) -- 0.5 trang
- NFR1: Thoi gian xu ly < 30 giay moi cua so 5 phut
- NFR2: Ty le false positive < 15%
- NFR3: Recall > 95% (khong bo sot tan cong)
- NFR4: He thong hoat dong lien tuc 24/7
- NFR5: De trien khai (Docker)

#### 3.1.3. Yeu cau phan cung va phan mem (Hardware & Software Requirements) -- 0.5 trang
**Hinh/Bang de xuat:**
- Bang 3.2: Yeu cau phan cung toi thieu
- Bang 3.3: Danh sach phan mem va phien ban

---

### 3.2. Kien truc he thong (System Architecture) -- 3 trang

#### 3.2.1. Kien truc tong the (Overall Architecture) -- 1.5 trang
**Noi dung chinh:**
- Kien truc 4 tang: Data Collection -> Processing -> Detection -> Response
- Luong du lieu: SSH Log -> Logstash -> Elasticsearch -> AI Engine -> Fail2Ban/Kibana
- Cac thanh phan chinh va tuong tac

**Hinh/Bang de xuat:**
- Hinh 3.1: So do kien truc tong the he thong (architecture diagram)
- Hinh 3.2: So do luong du lieu (data flow diagram)

#### 3.2.2. Kien truc Docker (Docker Architecture) -- 1 trang
**Noi dung chinh:**
- Docker Compose configuration
- Cac container: ssh-server, elasticsearch, logstash, kibana, ai-engine, fail2ban
- Mang noi bo (bridge network)
- Volume mapping

**Hinh/Bang de xuat:**
- Hinh 3.3: So do Docker Compose (container topology)
- Bang 3.4: Chi tiet cac container (ten, image, port, volume)

#### 3.2.3. Kien truc ELK Pipeline (ELK Pipeline Architecture) -- 0.5 trang
**Hinh/Bang de xuat:**
- Hinh 3.4: Pipeline Logstash chi tiet (input -> filter -> output)

---

### 3.3. Thiet ke du lieu (Data Design) -- 3 trang

#### 3.3.1. Nguon du lieu va thu thap (Data Source & Collection) -- 1 trang
**Noi dung chinh:**
- Nguon: /var/log/auth.log (SSH authentication log)
- Dinh dang log: timestamp, hostname, process, message
- Cach thu thap: Filebeat/Logstash doc truc tiep tu file log
- Pre-processing: parsing, timestamp normalization, field extraction

**Hinh/Bang de xuat:**
- Hinh 3.5: Vi du dinh dang auth.log (binh thuong vs tan cong)
- Bang 3.5: Cac truong du lieu trich xuat tu log goc

#### 3.3.2. Trich xuat dac trung -- 14 Features (Feature Engineering) -- 1.5 trang
**Noi dung chinh:**
- Cua so thoi gian: 5 phut (300 giay)
- Moi cua so tinh theo tung IP nguon
- 14 dac trung:

| # | Ten dac trung | Mo ta | Loai |
|---|---------------|-------|------|
| 1 | attempt_count | So lan thu dang nhap | Count |
| 2 | failure_rate | Ti le that bai | Ratio |
| 3 | unique_users | So luong user duy nhat | Count |
| 4 | mean_inter_attempt_time | Thoi gian trung binh giua cac lan thu | Temporal |
| 5 | min_inter_attempt_time | Thoi gian ngan nhat giua cac lan thu | Temporal |
| 6 | std_inter_attempt_time | Do lech chuan thoi gian giua cac lan thu | Temporal |
| 7 | session_duration_mean | Thoi gian phien trung binh | Temporal |
| 8 | session_duration_std | Do lech chuan thoi gian phien | Temporal |
| 9 | user_entropy | Entropy cua username distribution | Statistical |
| 10 | attempt_acceleration | Gia toc tan suat thu (tang/giam) | Temporal |
| 11 | max_burst_count | So lan thu lien tiep nhanh nhat (burst) | Count |
| 12 | unique_user_ratio | Ti le user duy nhat / tong so lan thu | Ratio |
| 13 | hour_of_day | Gio trong ngay (0-23) | Contextual |
| 14 | is_weekend | Ngay cuoi tuan (0/1) | Contextual |

- Ly do chon tung dac trung
- Quy trinh tinh toan

**Trich dan de xuat:**
- [42] Iglesias, F., & Zseby, T. (2015). "Analysis of network traffic features for anomaly detection." *Machine Learning*, 101(1), 59-84.
- [43] Garcia, S., Grill, M., Stiborek, J., & Zunino, A. (2014). "An empirical comparison of botnet detection methods." *Computers & Security*, 45, 100-123.

**Hinh/Bang de xuat:**
- Bang 3.6: Chi tiet 14 dac trung (ten, cong thuc, y nghia, kieu du lieu)
- Hinh 3.6: Quy trinh feature extraction pipeline

#### 3.3.3. Phan chia tap du lieu (Dataset Split) -- 0.5 trang
**Noi dung chinh:**
- Training set: 7,212 mau (chi du lieu binh thuong -- normal traffic)
- Test set: 15,184 mau (ti le normal:attack = 1:3)
- Ly do phan chia: semi-supervised -- chi hoc tu binh thuong
- Khong co validation set rieng (dung cross-validation tren train set)

**Hinh/Bang de xuat:**
- Bang 3.7: Thong ke tap du lieu (so mau, ti le, dac diem)
- Hinh 3.7: Bieu do phan phoi du lieu train vs test

---

### 3.4. Thiet ke mo hinh AI (AI Model Design) -- 3 trang

#### 3.4.1. Pipeline huan luyen (Training Pipeline) -- 1 trang
**Noi dung chinh:**
- Buoc 1: Data ingestion tu Elasticsearch
- Buoc 2: Feature extraction (14 features per IP per 5-min window)
- Buoc 3: Data preprocessing (scaling, handling missing values)
- Buoc 4: Model training (IF, LOF, OCSVM)
- Buoc 5: Model evaluation va lua chon
- Buoc 6: Model serialization (joblib)

**Hinh/Bang de xuat:**
- Hinh 3.8: So do pipeline huan luyen (flowchart)
- Bang 3.8: Sieu tham so cac mo hinh

#### 3.4.2. Thiet ke nguong dong EWMA-Adaptive Percentile (Dynamic Threshold Design) -- 1.5 trang
**Noi dung chinh:**
- Buoc 1: Mo hinh tinh anomaly score cho moi cua so
- Buoc 2: EWMA lam min chuoi anomaly scores: z_t = lambda * s_t + (1-lambda) * z_{t-1}
- Buoc 3: Tinh adaptive percentile tren cua so truot N cua so 5 phut gan nhat
- Buoc 4: So sanh z_t voi nguong dong -> quyet dinh canh bao
- Tham so: lambda (EWMA), q (percentile), N (window size)
- Logic 3 muc: Normal (z_t < P85), Warning (P85 <= z_t < P95), Alert (z_t >= P95)

**Hinh/Bang de xuat:**
- Hinh 3.9: So do chi tiet co che nguong dong (block diagram)
- Hinh 3.10: Vi du minh hoa nguong dong tren du lieu thoi gian thuc
- Bang 3.9: Tham so nguong dong va gia tri mac dinh

#### 3.4.3. Thiet ke pipeline phat hien thoi gian thuc (Real-time Detection Pipeline) -- 0.5 trang
**Hinh/Bang de xuat:**
- Hinh 3.11: Sequence diagram cua quy trinh phat hien

---

### 3.5. Thiet ke kich ban mo phong tan cong (Attack Simulation Design) -- 2 trang

#### 3.5.1. Moi truong mo phong (Simulation Environment) -- 0.5 trang
**Noi dung chinh:**
- Docker network topology
- Attacker container(s) vs Target SSH server
- Cong cu tan cong: Hydra, Medusa, custom Python script

#### 3.5.2. 5 kich ban tan cong (5 Attack Scenarios) -- 1.5 trang
**Noi dung chinh:**

| # | Kich ban | Mo ta | Cong cu | Do kho |
|---|----------|-------|---------|--------|
| 1 | Simple Brute-force | Tan cong nhanh, 1 IP, 1 user | Hydra | De |
| 2 | Dictionary Attack | Su dung wordlist lon, nhieu user | Hydra + wordlist | Trung binh |
| 3 | Slow & Low | Tan cong cham, trai deu thoi gian | Custom script | Kho |
| 4 | Distributed Attack | Nhieu IP nguon dong thoi | Nhieu container | Kho |
| 5 | Mixed/Adaptive | Ket hop cac kieu, thay doi toc do | Hybrid | Rat kho |

**Hinh/Bang de xuat:**
- Bang 3.10: Chi tiet 5 kich ban tan cong (tham so, thoi gian, ky vong)
- Hinh 3.12: So do moi truong mo phong tan cong

---

### 3.6. Thiet ke Dashboard Kibana (Dashboard Design) -- 2 trang
**Noi dung chinh:**
- Layout dashboard chinh: overview, real-time monitoring, historical analysis
- Cac visualization: line chart (anomaly score), pie chart (normal vs anomaly), geo map (IP), table (recent alerts)
- Alert configuration

**Hinh/Bang de xuat:**
- Hinh 3.13: Wireframe dashboard chinh (mockup)
- Hinh 3.14: Wireframe trang chi tiet canh bao
- Bang 3.11: Danh sach cac visualization va muc dich

---

## CHUONG 4: HIEN THUC HE THONG (System Implementation) -- 16-18 trang

### 4.1. Cai dat moi truong (Environment Setup) -- 2 trang

#### 4.1.1. Docker Compose Configuration -- 1 trang
**Noi dung chinh:**
- File docker-compose.yml chi tiet
- Cau hinh moi container (image, ports, volumes, environment)
- Network configuration
- Mo ta quy trinh khoi dong he thong

**Hinh/Bang de xuat:**
- Hinh 4.1: Cau truc thu muc du an (directory tree)
- Hinh 4.2: Docker Compose topology diagram thuc te

#### 4.1.2. Cau hinh ELK Stack -- 1 trang
**Noi dung chinh:**
- Elasticsearch: index settings, mapping cho SSH log
- Logstash: pipeline configuration (grok pattern cho auth.log)
- Kibana: index pattern, dashboard setup
- Grok pattern cho SSH log: %{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sshd\[%{NUMBER:pid}\]: %{GREEDYDATA:message}

**Hinh/Bang de xuat:**
- Hinh 4.3: Cau hinh Logstash pipeline (code snippet)
- Bang 4.1: Elasticsearch index mapping

---

### 4.2. Thu thap va xu ly du lieu (Data Collection & Processing) -- 3 trang

#### 4.2.1. Sinh du lieu binh thuong (Normal Data Generation) -- 1 trang
**Noi dung chinh:**
- Script mo phong hoat dong SSH binh thuong
- Cac pattern: dang nhap gio hanh chinh, it vao ban dem, it cuoi tuan
- So luong: 7,212 mau (5-min windows) cho training

**Hinh/Bang de xuat:**
- Hinh 4.4: Phan phoi thoi gian cua du lieu binh thuong
- Bang 4.2: Thong ke du lieu binh thuong (mean, std cua tung feature)

#### 4.2.2. Mo phong tan cong (Attack Simulation) -- 1 trang
**Noi dung chinh:**
- Script Hydra command cho tung kich ban
- Script Python custom cho slow & low attack
- Tham so: so luong thu, toc do, user list, password list

**Hinh/Bang de xuat:**
- Hinh 4.5: Vi du lenh Hydra cho kich ban 1
- Bang 4.3: Tham so mo phong cho 5 kich ban

#### 4.2.3. Feature Extraction Pipeline -- 1 trang
**Noi dung chinh:**
- Code Python trich xuat 14 dac trung
- Xu ly truong hop dac biet: cua so khong du du lieu, IP chi xuat hien 1 lan
- Normalization: StandardScaler

**Hinh/Bang de xuat:**
- Hinh 4.6: Code snippet trich xuat dac trung (Python)
- Hinh 4.7: Pipeline xu ly du lieu tu raw log den feature vector

---

### 4.3. Huan luyen mo hinh (Model Training) -- 4 trang

#### 4.3.1. Huan luyen Isolation Forest (Training IF -- Main Model) -- 1.5 trang
**Noi dung chinh:**
- Sieu tham so: n_estimators, max_samples, contamination, random_state
- Quy trinh toi uu hoa sieu tham so (Grid Search / manual tuning)
- Code huan luyen
- Gia tri sieu tham so cuoi cung

**Trich dan de xuat:**
- [13] Liu, F. T., et al. (2008) -- da trich o tren

**Hinh/Bang de xuat:**
- Hinh 4.8: Code huan luyen Isolation Forest
- Bang 4.4: Ket qua toi uu hoa sieu tham so IF
- Hinh 4.9: Anh huong cua n_estimators den hieu suat

#### 4.3.2. Huan luyen LOF va OCSVM (Training Benchmark Models) -- 1 trang
**Noi dung chinh:**
- LOF: n_neighbors, contamination
- OCSVM: kernel, nu, gamma
- Cung quy trinh huan luyen nhu IF

**Hinh/Bang de xuat:**
- Bang 4.5: Sieu tham so cuoi cung cua LOF va OCSVM

#### 4.3.3. Hien thuc nguong dong EWMA-Adaptive Percentile (Dynamic Threshold Implementation) -- 1.5 trang
**Noi dung chinh:**
- Code Python cho EWMA calculation
- Code Adaptive Percentile
- Logic ket hop va 3 muc canh bao
- Toi uu tham so lambda va percentile

**Hinh/Bang de xuat:**
- Hinh 4.10: Code EWMA-Adaptive Percentile
- Hinh 4.11: Bieu do anomaly score + nguong dong tren du lieu test
- Bang 4.6: Tham so nguong dong da toi uu

---

### 4.4. Tich hop Fail2Ban (Fail2Ban Integration) -- 2 trang

#### 4.4.1. Cau hinh Fail2Ban cho AI-driven banning -- 1 trang
**Noi dung chinh:**
- Custom jail configuration
- Custom filter dua tren AI alert
- Ban action: iptables rule
- Unban logic va thoi gian ban

**Hinh/Bang de xuat:**
- Hinh 4.12: File cau hinh Fail2Ban jail
- Hinh 4.13: Luong tich hop AI Engine -> Fail2Ban

#### 4.4.2. API ket noi AI Engine va Fail2Ban -- 1 trang
**Noi dung chinh:**
- Communication channel: file-based hoac API
- Format alert message
- Error handling va fallback

**Hinh/Bang de xuat:**
- Hinh 4.14: Sequence diagram AI -> Fail2Ban
- Bang 4.7: Format alert message

---

### 4.5. Hien thuc Dashboard Kibana (Kibana Dashboard Implementation) -- 2 trang
**Noi dung chinh:**
- Tao index pattern
- Cac visualization da tao:
  - Real-time anomaly score line chart
  - IP geolocation map
  - Top attacking IPs bar chart
  - Attack timeline
  - Feature importance heatmap
  - Alert history table
- Dashboard layout va navigation

**Hinh/Bang de xuat:**
- Hinh 4.15: Screenshot dashboard tong quan (overview)
- Hinh 4.16: Screenshot bieu do anomaly score thoi gian thuc
- Hinh 4.17: Screenshot bang canh bao
- Hinh 4.18: Screenshot phan tich IP tan cong

---

### 4.6. Tong hop cau truc ma nguon (Source Code Structure) -- 1 trang
**Noi dung chinh:**
- Cau truc thu muc du an
- Mo ta cac module chinh
- Huong dan chay he thong

**Hinh/Bang de xuat:**
- Hinh 4.19: Cau truc thu muc du an (tree diagram)
- Bang 4.8: Mo ta cac file/module chinh

---

## CHUONG 5: KET QUA VA DANH GIA (Results & Evaluation) -- 14-16 trang

### 5.1. Moi truong thu nghiem (Experimental Setup) -- 1 trang
**Noi dung chinh:**
- Cau hinh phan cung (CPU, RAM, OS)
- Phien ban phan mem
- Tap du lieu thu nghiem: 7,212 train + 15,184 test (ti le 1:3 normal:attack)
- Cac chi so danh gia: Precision, Recall, F1-score, ROC-AUC, Confusion Matrix, FPR

**Hinh/Bang de xuat:**
- Bang 5.1: Cau hinh moi truong thu nghiem
- Bang 5.2: Thong ke tap du lieu thu nghiem

---

### 5.2. Ket qua huan luyen mo hinh (Model Training Results) -- 3 trang

#### 5.2.1. Ket qua Isolation Forest -- 1 trang
**Noi dung chinh:**
- F1-score: 0.886
- Recall: 99.99%
- ROC-AUC: 0.832
- Confusion Matrix: chi tiet TP, TN, FP, FN
- Phan tich: Recall rat cao (gan nhu khong bo sot tan cong), nhung Precision thap hon (co false positive)
- Trade-off: chap nhan FP cao hon de dam bao an toan (khong bo sot)

**Hinh/Bang de xuat:**
- Bang 5.3: Classification report cua Isolation Forest
- Hinh 5.1: Confusion Matrix cua IF
- Hinh 5.2: ROC Curve cua IF

#### 5.2.2. Ket qua LOF -- 0.75 trang
**Noi dung chinh:**
- F1-score: 0.905
- Recall: 100%
- ROC-AUC: 0.976
- Phan tich: hieu suat tot nhat ve ROC-AUC, nhung cham hon IF

**Hinh/Bang de xuat:**
- Bang 5.4: Classification report cua LOF
- Hinh 5.3: Confusion Matrix cua LOF

#### 5.2.3. Ket qua One-Class SVM -- 0.75 trang
**Noi dung chinh:**
- F1-score: 0.913
- Recall: 100%
- ROC-AUC: 0.900
- Phan tich: F1 cao nhat, nhung thoi gian huan luyen lau nhat

**Hinh/Bang de xuat:**
- Bang 5.5: Classification report cua OCSVM
- Hinh 5.4: Confusion Matrix cua OCSVM

#### 5.2.4. So sanh ba mo hinh (Model Comparison) -- 0.5 trang
**Noi dung chinh:**
- So sanh toan dien: F1, Recall, Precision, ROC-AUC, thoi gian huan luyen, thoi gian inference
- Ly do chon IF lam mo hinh chinh: can bang giua hieu suat va toc do, phu hop thoi gian thuc
- LOF: ROC-AUC tot nhat nhung cham; OCSVM: F1 tot nhat nhung phuc tap

**Hinh/Bang de xuat:**
- Bang 5.6: So sanh tong hop ba mo hinh (bang chinh cua luan van)
- Hinh 5.5: Bieu do radar so sanh ba mo hinh
- Hinh 5.6: ROC Curves cua ba mo hinh tren cung bieu do

---

### 5.3. Phan tich dac trung quan trong (Feature Importance Analysis) -- 2 trang
**Noi dung chinh:**
- Phuong phap tinh: permutation importance, mean path length contribution
- Top 3 dac trung quan trong nhat:
  1. session_duration_mean: phan biet ro giua phien binh thuong (dai) va brute-force (ngan/khong co)
  2. min_inter_attempt_time: tan cong tu dong co thoi gian giua cac lan thu rat ngan
  3. mean_inter_attempt_time: tuong tu nhung on dinh hon
- Cac dac trung it quan trong: hour_of_day, is_weekend (tan cong khong phu thuoc thoi gian)
- Phan tich tuong quan giua cac dac trung

**Trich dan de xuat:**
- [44] Altmann, A., Tolosi, L., Sander, O., & Lengauer, T. (2010). "Permutation importance: a corrected feature importance measure." *Bioinformatics*, 26(10), 1340-1347.

**Hinh/Bang de xuat:**
- Hinh 5.7: Bieu do feature importance (horizontal bar chart)
- Hinh 5.8: Heatmap tuong quan giua 14 dac trung
- Hinh 5.9: Phan phoi top 3 dac trung: normal vs attack (violin plot/box plot)
- Bang 5.7: Xep hang 14 dac trung theo muc do quan trong

---

### 5.4. Hieu qua nguong dong va du doan som (Dynamic Threshold & Early Prediction Effectiveness) -- 3 trang

#### 5.4.1. Hieu qua EWMA-Adaptive Percentile -- 1.5 trang
**Noi dung chinh:**
- So sanh nguong co dinh vs nguong dong tren cung tap du lieu
- Ket qua: nguong dong giam false positive X% so voi nguong co dinh
- Kha nang tu dieu chinh khi phan phoi du lieu thay doi
- Anh huong cua tham so lambda

**Hinh/Bang de xuat:**
- Hinh 5.10: So sanh nguong co dinh vs nguong dong tren chuoi thoi gian
- Hinh 5.11: Anh huong cua lambda den do chinh xac
- Bang 5.8: So sanh chi so giua nguong co dinh va nguong dong

#### 5.4.2. Kha nang du doan som (Early Prediction Capability) -- 1.5 trang
**Noi dung chinh:**
- Do tre phat hien (detection latency) trung binh cho moi kich ban
- So sanh voi Fail2Ban mac dinh: phat hien som hon bao nhieu giay/phut
- Phan tich tung kich ban tan cong:
  - Kich ban 1 (Simple): phat hien trong 1-2 cua so (5-10 phut)
  - Kich ban 3 (Slow & Low): kho hon nhung van phat hien duoc
  - Kich ban 4 (Distributed): phat hien tung IP rieng le

**Hinh/Bang de xuat:**
- Hinh 5.12: Timeline phat hien cho tung kich ban (so sanh AI vs Fail2Ban)
- Bang 5.9: Do tre phat hien trung binh theo kich ban
- Hinh 5.13: Bieu do anomaly score theo thoi gian cho kich ban 3 (Slow & Low)

---

### 5.5. Ket qua 5 kich ban tan cong (5 Attack Scenario Results) -- 3 trang

#### 5.5.1. Kich ban 1: Simple Brute-force -- 0.5 trang
**Noi dung chinh:**
- Tham so tan cong, ket qua phat hien, thoi gian phat hien
- Anomaly score rat cao, phat hien ngay lap tuc

#### 5.5.2. Kich ban 2: Dictionary Attack -- 0.5 trang
**Noi dung chinh:**
- Dac diem: nhieu username khac nhau -> user_entropy cao
- Phat hien hieu qua

#### 5.5.3. Kich ban 3: Slow & Low Attack -- 0.75 trang
**Noi dung chinh:**
- Kich ban kho nhat
- Dac trung session_duration_mean va min_inter_attempt_time giup phan biet
- EWMA lam min anomaly score tang dan -> phat hien duoc

#### 5.5.4. Kich ban 4: Distributed Attack -- 0.75 trang
**Noi dung chinh:**
- Phat hien tung IP rieng le
- Thach thuc: moi IP it lan thu -> can ket hop nhieu dac trung

#### 5.5.5. Kich ban 5: Mixed/Adaptive Attack -- 0.5 trang
**Noi dung chinh:**
- Ket hop cac kieu: kiem tra do linh hoat cua mo hinh
- Ket qua tong hop

**Hinh/Bang de xuat (cho ca 5 kich ban):**
- Bang 5.10: Ket qua tong hop 5 kich ban (detection rate, latency, FP/FN)
- Hinh 5.14-5.18: Bieu do anomaly score theo thoi gian cho tung kich ban
- Hinh 5.19: Bieu do so sanh detection rate giua 5 kich ban

---

### 5.6. Danh gia hieu nang he thong (System Performance Evaluation) -- 1 trang
**Noi dung chinh:**
- Thoi gian xu ly trung binh moi cua so 5 phut
- Muc su dung tai nguyen: CPU, RAM, disk I/O
- Kha nang mo rong (scalability)
- So sanh voi Fail2Ban don thuan

**Hinh/Bang de xuat:**
- Bang 5.11: Hieu nang he thong (thoi gian xu ly, tai nguyen)
- Hinh 5.20: Bieu do su dung tai nguyen theo thoi gian

---

### 5.7. Thao luan (Discussion) -- 2 trang
**Noi dung chinh:**
- Tai sao IF duoc chon lam mo hinh chinh du F1 thap hon LOF va OCSVM
  - Toc do inference nhanh hon (phu hop real-time)
  - Khong can tinh khoang cach den tat ca diem (nhu LOF)
  - Do phuc tap thap hon OCSVM
- Phan tich false positives: nguyen nhan va cach giam thieu
- Dac trung session_duration_mean quan trong nhat: y nghia thuc tien
- Nguong dong EWMA: loi the va gioi han
- So sanh voi cac nghien cuu truoc do (tro lai bang 2.8)
- Han che cua nghien cuu:
  - Du lieu mo phong, chua xac minh tren du lieu thuc
  - Chua xu ly IPv6, VPN/Tor
  - Cua so 5 phut co the khong toi uu cho moi truong hop

**Trich dan de xuat:**
- Trich dan lai cac nghien cuu o muc 2.5 de so sanh

---

## CHUONG 6: KET LUAN VA HUONG PHAT TRIEN (Conclusion & Future Work) -- 5-6 trang

### 6.1. Ket luan (Conclusion) -- 2 trang
**Noi dung chinh:**
- Tom tat van de nghien cuu va dong co
- Tom tat phuong phap: semi-supervised anomaly detection voi IF, nguong dong EWMA-Adaptive Percentile
- Tom tat ket qua chinh:
  - IF dat Recall 99.99%, F1 0.886 -- du tot cho ung dung thuc te
  - 3 dac trung quan trong nhat: session_duration_mean, min_inter_attempt_time, mean_inter_attempt_time
  - Nguong dong cai thien hieu qua phat hien so voi nguong co dinh
  - He thong tich hop end-to-end hoat dong tot voi 5 kich ban tan cong
  - Docker hoa giup de dang trien khai
- Dong gop chinh cua luan van:
  1. Bo 14 dac trung hieu qua cho SSH brute-force detection
  2. Phuong phap nguong dong EWMA-Adaptive Percentile cho du doan som
  3. He thong tich hop hoan chinh: AI + ELK + Fail2Ban + Docker

---

### 6.2. Nhung dong gop cua luan van (Contributions) -- 1 trang
**Noi dung chinh:**
- Dong gop ly thuyet:
  - Phuong phap ket hop EWMA-Adaptive Percentile
  - Phan tich so sanh IF vs LOF vs OCSVM trong boi canh SSH
- Dong gop thuc tien:
  - He thong san sang trien khai (production-ready prototype)
  - Bo dac trung co the tai su dung cho nghien cuu khac
  - Ma nguon mo (open source)

---

### 6.3. Han che (Limitations) -- 1 trang
**Noi dung chinh:**
- Du lieu mo phong, chua kiem chung tren moi truong thuc te quy mo lon
- Chi tap trung SSH brute-force, chua mo rong sang cac loai tan cong khac
- Chua xu ly cac ky thuat ne tranh (evasion techniques) phuc tap
- Cua so 5 phut co the qua dai cho tan cong rat nhanh hoac qua ngan cho tan cong rat cham
- Chua co co che tu hoc (online learning) -- mo hinh can huan luyen lai dinh ky
- Chua danh gia tren du lieu IPv6, Tor, VPN

---

### 6.4. Huong phat trien tuong lai (Future Work) -- 2 trang
**Noi dung chinh:**
1. **Mo rong sang cac giao thuc khac:** RDP, FTP, HTTP authentication
2. **Ung dung Deep Learning:** Autoencoder, LSTM-based anomaly detection cho chuoi thoi gian
3. **Online Learning:** Mo hinh tu cap nhat voi du lieu moi (Incremental Isolation Forest)
4. **Adaptive window size:** Tu dong dieu chinh kich thuoc cua so theo tinh hinh
5. **Federated Learning:** Hoc tu nhieu he thong ma khong chia se du lieu
6. **Thu nghiem production:** Trien khai tren moi truong thuc (cloud VM, enterprise network)
7. **Threat Intelligence integration:** Ket hop voi blacklist IP, threat feed
8. **Explainable AI (XAI):** Giai thich ly do phat hien cho SOC analyst

**Trich dan de xuat:**
- [45] Nassif, A. B., Talib, M. A., Nasir, Q., & Dakalbab, F. M. (2021). "Machine learning for anomaly detection: A systematic review." *IEEE Access*, 9, 78658-78700.
- [46] Mothukuri, V., Parizi, R. M., Pouriyeh, S., Huang, Y., Dehghantanha, A., & Srivastava, G. (2021). "A survey on security and privacy of federated learning." *Future Generation Computer Systems*, 115, 619-640.

---

## TAI LIEU THAM KHAO (References) -- 3-4 trang

### Danh sach tai lieu tham khao de xuat (46+ tai lieu)

**Sach va tai lieu tham khao chinh (Books & Standards):**
- [7] OWASP Foundation. (2023). *Brute Force Attack*.
- [8] Ylonen, T., & Lonvick, C. (2006). RFC 4251 - SSH Protocol Architecture.
- [23] Gormley, C., & Tong, Z. (2015). *Elasticsearch: The Definitive Guide*.
- [25] Fail2Ban Documentation. https://www.fail2ban.org/
- [26] Merkel, D. (2014). Docker: Lightweight Linux containers.

**Bai bao Q1-Q2 (High-impact journals):**
- [4] Chandola et al. (2009). Anomaly detection survey. *ACM Computing Surveys* (Q1).
- [5] Goldstein & Uchida (2016). Comparative evaluation. *PLoS ONE* (Q1).
- [11] Pang et al. (2021). Deep learning for anomaly detection. *ACM Computing Surveys* (Q1).
- [13] Liu et al. (2008). Isolation Forest. *IEEE ICDM* (Top conference).
- [14] Liu et al. (2012). Isolation-based anomaly detection. *ACM TKDD* (Q1).
- [15] Hariri et al. (2021). Extended Isolation Forest. *IEEE TKDE* (Q1).
- [16] Breunig et al. (2000). LOF. *ACM SIGMOD* (Top conference).
- [17] Scholkopf et al. (2001). One-Class SVM. *Neural Computation* (Q1).
- [28] Sperotto et al. (2010). IP flow-based IDS. *IEEE COMST* (Q1).
- [30] Ring et al. (2019). IDS datasets survey. *Computers & Security* (Q1).
- [33] Alhajjar et al. (2021). Adversarial ML in NIDS. *Expert Systems with Applications* (Q1).
- [35] Buczak & Guven (2016). Data mining for cyber security. *IEEE COMST* (Q1).
- [37] Ahmed et al. (2016). Network anomaly detection survey. *JNCA* (Q1).
- [45] Nassif et al. (2021). ML for anomaly detection review. *IEEE Access* (Q2).

**Bai bao Q2-Q3:**
- [18] Tax & Duin (2004). Support vector data description. *Machine Learning* (Q1).
- [22] Ahmad et al. (2017). Real-time anomaly detection. *Neurocomputing* (Q2).
- [29] Kumari & Jain (2023). DDoS attacks survey. *Computers & Security* (Q1).
- [32] Bezerra et al. (2019). IoTDS: One-class for botnets. *Sensors* (Q2).
- [34] Sarker (2021). ML algorithms survey. *SN Computer Science* (Q3).
- [36] Idhammad et al. (2018). Semi-supervised DDoS detection. *Applied Intelligence* (Q2).
- [42] Iglesias & Zseby (2015). Network traffic features. *Machine Learning* (Q1).
- [46] Mothukuri et al. (2021). Federated learning security. *FGCS* (Q1).

**Tai lieu tieng Viet:**
- [38] Nguyen Huy Trung, Nguyen Minh Hai. (2021). *Tap chi KH&CN - DH Da Nang*.
- [39] Le Hai Viet, Pham Van Hau. (2022). *Ky yeu VNISA*.
- [40] Tran Minh Triet, Nguyen Thanh Son. (2020). *Tap chi PT KH&CN - DHQG TP.HCM*.
- [41] Vu Thanh Nguyen et al. (2023). *Journal of Science and Technology on Information Security*.

**Bao cao nganh:**
- [1] Verizon. (2024). *Data Breach Investigations Report*.

*Luu y: Dinh dang trich dan theo IEEE hoac APA 7th edition tuy theo yeu cau cua FPT University.*

---

## PHU LUC (Appendices) -- 5-8 trang

### Phu luc A: Ma nguon chinh (Key Source Code) -- 3 trang
- A.1: Feature extraction module (Python)
- A.2: Isolation Forest training script
- A.3: EWMA-Adaptive Percentile implementation
- A.4: Fail2Ban integration script
- A.5: Docker Compose file

### Phu luc B: Cau hinh he thong (System Configuration) -- 1 trang
- B.1: Logstash pipeline configuration
- B.2: Fail2Ban jail configuration
- B.3: Elasticsearch index mapping

### Phu luc C: Ket qua chi tiet (Detailed Results) -- 1-2 trang
- C.1: Full classification reports
- C.2: Chi tiet tung kich ban tan cong
- C.3: Thong ke du lieu mau

### Phu luc D: Huong dan cai dat va su dung (Installation Guide) -- 1-2 trang
- D.1: Yeu cau tien quyet
- D.2: Cai dat tu Docker Compose
- D.3: Huong dan su dung dashboard

---

## TONG HOP HINH ANH VA BANG BIEU

### Danh muc hinh anh du kien (List of Figures) -- 35+ hinh

| STT | Ma hinh | Mo ta | Chuong |
|-----|---------|-------|--------|
| 1   | 1.1 | Thong ke tan cong brute-force SSH toan cau | 1 |
| 2   | 1.2 | So sanh timeline phat hien rule-based vs AI | 1 |
| 3   | 1.3 | So do muc tieu nghien cuu | 1 |
| 4   | 1.4 | Quy trinh nghien cuu | 1 |
| 5   | 1.5 | Gantt chart | 1 |
| 6   | 2.1 | Quy trinh tan cong brute-force SSH | 2 |
| 7   | 2.2 | Kien truc giao thuc SSH | 2 |
| 8   | 2.3 | Vi du log SSH bi tan cong | 2 |
| 9   | 2.4 | Phan loai anomaly detection | 2 |
| 10  | 2.5 | Supervised vs semi-supervised vs unsupervised | 2 |
| 11  | 2.6 | Nguyen ly Isolation Forest | 2 |
| 12  | 2.7 | Quy trinh xay dung iTree | 2 |
| 13  | 2.8 | Minh hoa LOF | 2 |
| 14  | 2.9 | Minh hoa One-Class SVM | 2 |
| 15  | 2.10 | EWMA voi cac gia tri lambda | 2 |
| 16  | 2.11 | EWMA control chart | 2 |
| 17  | 2.12 | Ket hop EWMA + Adaptive Percentile | 2 |
| 18  | 2.13 | Nguong co dinh vs nguong dong | 2 |
| 19  | 2.14 | Timeline phat hien truyen thong vs du doan som | 2 |
| 20  | 2.15 | Kien truc ELK Stack | 2 |
| 21  | 2.16 | Pipeline Logstash | 2 |
| 22  | 2.17 | Luong xu ly Fail2Ban | 2 |
| 23  | 2.18 | Kien truc Docker | 2 |
| 24  | 3.1 | Kien truc tong the he thong | 3 |
| 25  | 3.2 | Luong du lieu | 3 |
| 26  | 3.3 | Docker Compose topology | 3 |
| 27  | 3.4 | Pipeline Logstash chi tiet | 3 |
| 28  | 3.5 | Dinh dang auth.log | 3 |
| 29  | 3.6 | Feature extraction pipeline | 3 |
| 30  | 3.7 | Phan phoi du lieu train vs test | 3 |
| 31  | 3.8 | Pipeline huan luyen | 3 |
| 32  | 3.9 | Co che nguong dong | 3 |
| 33  | 3.10 | Vi du nguong dong thoi gian thuc | 3 |
| 34  | 3.11 | Sequence diagram phat hien | 3 |
| 35  | 3.12 | Moi truong mo phong tan cong | 3 |
| 36  | 3.13 | Wireframe dashboard chinh | 3 |
| 37  | 3.14 | Wireframe trang chi tiet canh bao | 3 |
| 38  | 4.1 | Cau truc thu muc du an | 4 |
| 39  | 4.2 | Docker Compose topology thuc te | 4 |
| 40  | 4.3 | Cau hinh Logstash | 4 |
| 41  | 4.4 | Phan phoi du lieu binh thuong | 4 |
| 42  | 4.5 | Lenh Hydra | 4 |
| 43  | 4.6 | Code feature extraction | 4 |
| 44  | 4.7 | Pipeline xu ly du lieu | 4 |
| 45  | 4.8 | Code huan luyen IF | 4 |
| 46  | 4.9 | Anh huong n_estimators | 4 |
| 47  | 4.10 | Code EWMA-Adaptive Percentile | 4 |
| 48  | 4.11 | Anomaly score + nguong dong | 4 |
| 49  | 4.12 | Cau hinh Fail2Ban jail | 4 |
| 50  | 4.13 | Luong tich hop AI-Fail2Ban | 4 |
| 51  | 4.14 | Sequence diagram AI-Fail2Ban | 4 |
| 52  | 4.15 | Dashboard tong quan | 4 |
| 53  | 4.16 | Bieu do anomaly score real-time | 4 |
| 54  | 4.17 | Bang canh bao | 4 |
| 55  | 4.18 | Phan tich IP tan cong | 4 |
| 56  | 4.19 | Cau truc thu muc | 4 |
| 57  | 5.1 | Confusion Matrix IF | 5 |
| 58  | 5.2 | ROC Curve IF | 5 |
| 59  | 5.3 | Confusion Matrix LOF | 5 |
| 60  | 5.4 | Confusion Matrix OCSVM | 5 |
| 61  | 5.5 | Radar chart so sanh 3 mo hinh | 5 |
| 62  | 5.6 | ROC Curves 3 mo hinh | 5 |
| 63  | 5.7 | Feature importance bar chart | 5 |
| 64  | 5.8 | Feature correlation heatmap | 5 |
| 65  | 5.9 | Top 3 features distribution | 5 |
| 66  | 5.10 | Nguong co dinh vs nguong dong | 5 |
| 67  | 5.11 | Anh huong cua lambda | 5 |
| 68  | 5.12 | Timeline phat hien theo kich ban | 5 |
| 69  | 5.13 | Anomaly score kich ban Slow & Low | 5 |
| 70  | 5.14-5.18 | Anomaly score 5 kich ban | 5 |
| 71  | 5.19 | So sanh detection rate 5 kich ban | 5 |
| 72  | 5.20 | Su dung tai nguyen he thong | 5 |

### Danh muc bang bieu du kien (List of Tables) -- 20+ bang

| STT | Ma bang | Mo ta | Chuong |
|-----|---------|-------|--------|
| 1   | 1.1 | So sanh phuong phap phong chong brute-force | 1 |
| 2   | 2.1 | Phan loai tan cong brute-force | 2 |
| 3   | 2.2 | So sanh phuong phap phong chong truyen thong | 2 |
| 4   | 2.3 | Sieu tham so Isolation Forest | 2 |
| 5   | 2.4 | So sanh IF vs LOF vs OCSVM | 2 |
| 6   | 2.5 | Cac muc canh bao va hanh dong | 2 |
| 7   | 2.6 | Docker container va chuc nang | 2 |
| 8   | 2.7 | Thu vien Python va phien ban | 2 |
| 9   | 2.8 | Tong hop nghien cuu quoc te | 2 |
| 10  | 2.9 | Tong hop nghien cuu trong nuoc | 2 |
| 11  | 2.10 | Research gap analysis | 2 |
| 12  | 3.1 | Yeu cau chuc nang | 3 |
| 13  | 3.2 | Yeu cau phan cung | 3 |
| 14  | 3.3 | Phan mem va phien ban | 3 |
| 15  | 3.4 | Chi tiet Docker container | 3 |
| 16  | 3.5 | Truong du lieu tu log goc | 3 |
| 17  | 3.6 | Chi tiet 14 dac trung | 3 |
| 18  | 3.7 | Thong ke tap du lieu | 3 |
| 19  | 3.8 | Sieu tham so cac mo hinh | 3 |
| 20  | 3.9 | Tham so nguong dong | 3 |
| 21  | 3.10 | Chi tiet 5 kich ban tan cong | 3 |
| 22  | 3.11 | Danh sach visualization Kibana | 3 |
| 23  | 4.1 | Elasticsearch index mapping | 4 |
| 24  | 4.2 | Thong ke du lieu binh thuong | 4 |
| 25  | 4.3 | Tham so mo phong 5 kich ban | 4 |
| 26  | 4.4 | Ket qua toi uu sieu tham so IF | 4 |
| 27  | 4.5 | Sieu tham so LOF va OCSVM | 4 |
| 28  | 4.6 | Tham so nguong dong da toi uu | 4 |
| 29  | 4.7 | Format alert message | 4 |
| 30  | 4.8 | Mo ta cac module chinh | 4 |
| 31  | 5.1 | Cau hinh moi truong thu nghiem | 5 |
| 32  | 5.2 | Thong ke tap du lieu thu nghiem | 5 |
| 33  | 5.3 | Classification report IF | 5 |
| 34  | 5.4 | Classification report LOF | 5 |
| 35  | 5.5 | Classification report OCSVM | 5 |
| 36  | 5.6 | So sanh tong hop ba mo hinh | 5 |
| 37  | 5.7 | Xep hang 14 dac trung | 5 |
| 38  | 5.8 | So sanh nguong co dinh vs nguong dong | 5 |
| 39  | 5.9 | Do tre phat hien theo kich ban | 5 |
| 40  | 5.10 | Ket qua tong hop 5 kich ban | 5 |
| 41  | 5.11 | Hieu nang he thong | 5 |

---

## GHI CHU HUONG DAN VIET (Writing Guidelines)

### Phong cach viet:
- **Ngoi thu 3:** "Nghien cuu nay...", "Luan van trinh bay...", "He thong duoc thiet ke..."
- **Thoi hien tai** cho phan ly thuyet, **thoi qua khu** cho phan thuc nghiem
- Tranh dung tu nghe (jargon) khi khong can thiet, giai thich khi dung lan dau
- Moi khang dinh can co trich dan hoac so lieu ho tro

### Dinh dang FPT University:
- Font: Times New Roman 13pt
- Dan dong: 1.5
- Le trang: Trai 3cm, Phai 2cm, Tren 2cm, Duoi 2cm
- Danh so trang: giua, cuoi trang
- Trich dan: IEEE style hoac APA 7th (kiem tra voi GVHD)
- Hinh va bang: danh so theo chuong (Hinh 2.1, Bang 3.2...)

### Muc tieu so trang theo chuong:
- Chuong 2 (Co so ly thuyet) nen la chuong dai nhat: 18-22 trang
- Chuong 4 (Hien thuc) va Chuong 5 (Ket qua) moi chuong 14-18 trang
- Chuong 1 va 6: ngan gon, suc tich

### Checklist truoc khi nop:
- [ ] Tong so trang >= 85
- [ ] Tat ca hinh va bang duoc trich dan trong van ban
- [ ] Tat ca trich dan trong van ban co trong danh muc tai lieu tham khao
- [ ] Danh muc tu viet tat day du
- [ ] So thu tu hinh, bang lien tuc trong moi chuong
- [ ] Loi chinh ta va ngu phap
- [ ] Dinh dang nhat quan (font, co chu, dan dong)
- [ ] Trang bia dung mau FPT
- [ ] Tom tat (abstract) ca tieng Viet va tieng Anh
- [ ] Phu luc day du

---

*De cuong nay duoc thiet ke de mo rong thanh luan van day du 90-100+ trang. Moi muc con (sub-section) nen duoc viet thanh 0.5-2 trang tuy theo do quan trong va do phuc tap.*

*Ngay tao: 2026-04-03*
*Phien ban: 1.0*
