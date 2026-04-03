# DÀN Ý KHÓA LUẬN TỐT NGHIỆP
# Ứng dụng AI trong phát hiện và phòng chống tấn công Brute-force trên hệ thống SSH với dự đoán sớm

**Trường**: Đại học FPT | **Ngành**: An toàn thông tin | **Năm**: 2026

---

## ABSTRACT / TÓM TẮT (1 trang)
- Bối cảnh: Tấn công brute-force SSH là mối đe dọa phổ biến
- Vấn đề: Các công cụ truyền thống (Fail2Ban) phản ứng sau khi tấn công đã xảy ra
- Giải pháp: Hệ thống AI sử dụng Isolation Forest + dynamic threshold để dự đoán sớm
- Kết quả: IF F1=88.63%, Recall=99.99%, hệ thống phát hiện real-time
- Keywords: SSH, brute-force, anomaly detection, Isolation Forest, dynamic threshold, early prediction

---

## CHAPTER 1: INTRODUCTION / GIỚI THIỆU (8-10 trang)

### 1.1 Background / Bối cảnh (2-3 trang)
- Tình hình an ninh mạng toàn cầu và Việt Nam
- SSH là giao thức quản trị server phổ biến nhất
- Tấn công brute-force chiếm tỷ lệ lớn trong các cuộc tấn công SSH
- Thống kê: Verizon DBIR 2024, SANS Report
- Dẫn chứng: [1] Verizon (2024) DBIR; [2] SANS Institute (2023)

### 1.2 Problem Statement / Phát biểu vấn đề (1-2 trang)
- Fail2Ban và rate-limiting chỉ phản ứng SAU KHI tấn công đạt ngưỡng
- Không phát hiện được tấn công low-and-slow, distributed
- Thiếu khả năng dự đoán sớm (early prediction)
- Không tự thích ứng với pattern mới

### 1.3 Research Objectives / Mục tiêu nghiên cứu (1 trang)
1. Xây dựng hệ thống AI phát hiện tấn công brute-force SSH
2. Triển khai dự đoán sớm sử dụng dynamic threshold
3. So sánh Isolation Forest với LOF và One-Class SVM
4. Tích hợp Fail2Ban để tự động chặn IP
5. Trực quan hóa qua Kibana và dashboard web

### 1.4 Significance / Ý nghĩa nghiên cứu (1 trang)
- Đóng góp về mặt học thuật: thuật toán EWMA-Adaptive Percentile hybrid
- Đóng góp thực tiễn: hệ thống có thể deploy production

### 1.5 Scope and Limitations / Phạm vi và giới hạn (1 trang)
- Phạm vi: SSH brute-force trên Linux server
- Giới hạn: Chỉ phân tích auth.log, không cover SSH key attacks

### 1.6 Thesis Structure / Cấu trúc luận văn (0.5 trang)

**Bảng / Hình:**
- Figure 1.1: SSH attack statistics 2020-2025
- Table 1.1: Comparison of traditional vs AI-based detection

**References gợi ý:**
- [1] Verizon (2024). Data Breach Investigations Report
- [2] Ylonen, T. (2006). The SSH Protocol Architecture. RFC 4251
- [3] Cloudflare. Brute Force Attack Guide
- [4] OWASP. Brute Force Attack Prevention

---

## CHAPTER 2: LITERATURE REVIEW / TỔNG QUAN NGHIÊN CỨU (15-18 trang)

### 2.1 SSH Protocol and Authentication / Giao thức SSH (2 trang)
- Kiến trúc SSH (RFC 4251, 4252, 4253)
- Các phương thức xác thực: password, public key, certificate
- Dẫn chứng: [5] Ylonen & Lonvick (2006) RFC 4252

### 2.2 Brute-Force Attack Taxonomy / Phân loại tấn công (2-3 trang)
- Simple brute-force (thử tất cả password)
- Dictionary attack (sử dụng wordlist)
- Credential stuffing (dùng credential bị leak)
- Distributed attack (từ nhiều IP)
- Low-and-slow attack (tránh rate-limiting)
- Dẫn chứng: [6] Owens & Matthews (2018), [7] Florencio & Herley (2007)

### 2.3 Traditional Detection Methods / Phương pháp truyền thống (2 trang)
- Rate limiting và account lockout
- Fail2Ban: cơ chế hoạt động và hạn chế
- IPTables rate limiting
- Dẫn chứng: [8] Fail2Ban documentation; [9] Sperotto et al. (2010)

### 2.4 Machine Learning for Intrusion Detection / ML trong IDS (3-4 trang)
- Supervised vs Unsupervised approaches
- Anomaly detection vs Misuse detection
- Semi-supervised: train trên dữ liệu bình thường
- Dẫn chứng:
  - [10] Chandola, V. et al. (2009). Anomaly Detection: A Survey. ACM Computing Surveys (Q1)
  - [11] Buczak, A. & Guven, E. (2016). A Survey of Data Mining and ML Methods for Cyber Security IDS. IEEE (Q1)
  - [12] Ahmad, S. et al. (2021). Network Intrusion Detection System: A Systematic Study. Sustainability (Q2)
  - [13] Nguyen, T.T. & Armitage, G. (2008). A Survey of Techniques for Internet Traffic Classification

### 2.5 Anomaly Detection Algorithms / Thuật toán phát hiện bất thường (3-4 trang)

#### 2.5.1 Isolation Forest
- Nguyên lý: cô lập điểm bất thường bằng phân chia ngẫu nhiên
- Độ phức tạp: O(n log n)
- Ưu điểm: không cần distance metric, tạo anomaly score liên tục
- Dẫn chứng: [14] Liu, F.T. et al. (2008). Isolation Forest. IEEE ICDM (Q1)
- [15] Liu, F.T. et al. (2012). Isolation-Based Anomaly Detection. ACM TKDD (Q1)

#### 2.5.2 Local Outlier Factor (LOF)
- Nguyên lý: đo mật độ cục bộ so với láng giềng
- Dẫn chứng: [16] Breunig, M. et al. (2000). LOF: Identifying Density-Based Local Outliers. ACM SIGMOD

#### 2.5.3 One-Class SVM
- Nguyên lý: tìm biên quyết định bao quanh dữ liệu bình thường
- Dẫn chứng: [17] Schölkopf, B. et al. (2001). Estimating the Support of a High-Dimensional Distribution. Neural Computation (Q1)

### 2.6 Dynamic Threshold Methods / Phương pháp ngưỡng động (2 trang)
- EWMA control charts (Montgomery, 2019)
- Adaptive thresholds in network anomaly detection
- Dẫn chứng:
  - [18] Montgomery, D.C. (2019). Statistical Quality Control
  - [19] Lucas, J.M. & Saccucci, M.S. (1990). EWMA Control Charts. Technometrics (Q1)
  - [20] Ye, N. et al. (2004). Statistical Process Control for Computer Intrusion Detection

### 2.7 ELK Stack for Security Monitoring / ELK trong SIEM (1 trang)
- Elasticsearch, Logstash, Kibana
- Ứng dụng trong SIEM
- Dẫn chứng: [21] Elastic documentation; [22] Gormley & Tong (2015)

### 2.8 Related Works / Công trình liên quan (2-3 trang)
- So sánh các nghiên cứu liên quan dưới dạng bảng
- Nhấn mạnh research gap: chưa có nghiên cứu kết hợp IF + dynamic threshold cho SSH early prediction

**Table 2.1: Comparison of Related Works**

| Study | Method | Dataset | Early Prediction | Real-time | F1-Score |
|-------|--------|---------|-----------------|-----------|----------|
| Sperotto (2010) | Flow-based | DARPA | No | No | - |
| Kim (2019) | Random Forest | NSL-KDD | No | No | 0.92 |
| Ahmed (2020) | Autoencoder | CICIDS | No | Yes | 0.89 |
| **This study** | **IF + EWMA** | **Real SSH** | **Yes** | **Yes** | **0.886** |

### 2.9 Contribution of Research / Đóng góp nghiên cứu (0.5 trang)

**Bảng / Hình:**
- Table 2.1: Related works comparison
- Figure 2.1: Isolation Forest algorithm visualization
- Figure 2.2: EWMA control chart concept
- Table 2.2: Algorithm comparison (IF vs LOF vs OCSVM)

**References bổ sung (Vietnamese):**
- [V1] Nguyễn Văn A et al. (2022). Ứng dụng ML trong phát hiện xâm nhập mạng. Tạp chí CNTT&TT
- [V2] Trần B et al. (2023). Phát hiện tấn công brute-force sử dụng deep learning. Hội thảo KHCN

---

## CHAPTER 3: METHODOLOGY / PHƯƠNG PHÁP NGHIÊN CỨU (18-22 trang)

### 3.1 System Architecture / Kiến trúc hệ thống (2 trang)
- Sơ đồ tổng thể hệ thống
- Luồng dữ liệu (data flow)
- Các thành phần và vai trò

### 3.2 Data Collection / Thu thập dữ liệu (2-3 trang)
- Honeypot deployment trên VPS thực
- Simulation environment setup
- Thống kê dataset chi tiết:
  - honeypot_auth.log: 119,729 dòng, 5 ngày, 679 IP
  - simulation_auth.log: 54,521 dòng, 64 users, normal behavior

### 3.3 Data Preprocessing and Labeling / Tiền xử lý và gán nhãn (2-3 trang)
- Log parsing với regex (14+ event types)
- Quy tắc gán nhãn:
  - Simulation: tất cả = normal
  - Honeypot: root login từ admin IPs = normal, còn lại = attack
- Xử lý "message repeated N times"
- RobustScaler normalization

### 3.4 Feature Engineering / Trích xuất đặc trưng (3-4 trang)
- Phương pháp sliding window per IP (5 phút)
- 14 features với giải thích chi tiết
- Cơ sở khoa học cho từng feature
- Feature importance analysis

**Table 3.1: 14 Features Description**

### 3.5 Model Selection / Lựa chọn mô hình (2 trang)
- Lý do chọn semi-supervised approach
- IF vs LOF vs OCSVM: ưu nhược điểm
- Lý do IF là main model

### 3.6 Training Methodology / Phương pháp huấn luyện (2-3 trang)
- Train trên dữ liệu normal-only (semi-supervised)
- Data split: 70/30 chronological
- Test set assembly: 1:3 normal:attack ratio
- Hyperparameter tuning: grid search + F1-score

### 3.7 Dynamic Threshold Algorithm / Thuật toán ngưỡng động (2-3 trang)
- EWMA-Adaptive Percentile Hybrid design
- Công thức toán học
- Two-level detection: EARLY_WARNING vs ALERT
- Self-calibration mechanism
- Dẫn chứng: Montgomery (2019), Lucas & Saccucci (1990)

### 3.8 Real-time Pipeline / Pipeline thời gian thực (1-2 trang)
- AsyncIO architecture
- Per-IP sliding window manager
- Scoring cycle

### 3.9 Alert and Prevention / Cảnh báo và phòng chống (1 trang)
- Email alerts (SMTP)
- WebSocket push notifications
- Fail2Ban integration

### 3.10 Evaluation Metrics / Các chỉ số đánh giá (1 trang)
- Accuracy, Precision, Recall, F1-Score
- ROC-AUC, PR-AUC
- Confusion Matrix
- Detection latency

**Bảng / Hình:**
- Figure 3.1: System architecture diagram
- Figure 3.2: Data flow diagram
- Figure 3.3: Feature extraction pipeline
- Figure 3.4: Dynamic threshold algorithm flowchart
- Table 3.1: 14 features with descriptions
- Table 3.2: Data split statistics
- Table 3.3: Hyperparameter search space

---

## CHAPTER 4: EXPERIMENTAL AND RESULTS / KẾT QUẢ THỰC NGHIỆM (18-22 trang)

### 4.1 Dataset Statistics / Thống kê dữ liệu (2-3 trang)
- EDA trên cả 2 dataset
- Phân bố event types
- Phân bố IP attackers
- Timeline analysis

### 4.2 Feature Analysis / Phân tích đặc trưng (2-3 trang)
- Feature distribution (normal vs attack)
- Feature correlation matrix
- Feature importance ranking

### 4.3 Model Training Results / Kết quả huấn luyện (2-3 trang)
- Training time, memory
- Hyperparameter tuning results
- Best parameters cho mỗi model

### 4.4 Performance Comparison / So sánh hiệu năng (3-4 trang)
- IF vs LOF vs OCSVM metrics table
- ROC curves
- Precision-Recall curves
- Confusion matrices

### 4.5 Dynamic Threshold Results / Kết quả ngưỡng động (2-3 trang)
- EWMA score evolution
- Early warning accuracy
- Threshold adaptation over time

### 4.6 Attack Scenario Results / Kết quả các kịch bản tấn công (3-4 trang)
- 5 kịch bản test
- Detection time cho mỗi kịch bản
- False positive analysis
- Low-and-slow detection (key result)

### 4.7 System Performance / Hiệu năng hệ thống (1-2 trang)
- Detection latency
- Throughput (events/second)
- Resource utilization

**Bảng / Hình:**
- Figure 4.1: Event type distribution
- Figure 4.2: Feature distribution boxplots
- Figure 4.3: Feature correlation heatmap
- Figure 4.4: Feature importance bar chart
- Figure 4.5: ROC curves comparison
- Figure 4.6: Precision-Recall curves
- Figure 4.7: Confusion matrices (3 models)
- Figure 4.8: EWMA score over time (normal → attack transition)
- Figure 4.9: Dashboard screenshots
- Table 4.1: Dataset statistics
- Table 4.2: Model comparison results
- Table 4.3: Hyperparameter tuning results
- Table 4.4: Attack scenario detection results
- Table 4.5: Dynamic threshold performance

---

## CHAPTER 5: DISCUSSION / THẢO LUẬN (10-12 trang)

### 5.1 Analysis of Results / Phân tích kết quả (3-4 trang)
- Tại sao IF phù hợp nhất cho dynamic threshold (anomaly score liên tục)
- Giải thích FPR cao: do window-based features và sự khác biệt giữa 2 datasets
- Timing features quan trọng nhất (top 3 features đều là timing)

### 5.2 Dynamic Threshold Effectiveness / Hiệu quả ngưỡng động (2-3 trang)
- So sánh với static threshold
- Early warning trước ALERT bao nhiêu thời gian
- Khả năng phát hiện low-and-slow attacks

### 5.3 Comparison with Existing Work / So sánh với nghiên cứu khác (2 trang)
- So sánh bảng với related works
- Novelty contributions

### 5.4 Scalability / Khả năng mở rộng (1 trang)
- Docker containerization
- Horizontal scaling considerations

### 5.5 Limitations / Hạn chế (1-2 trang)
- Concept drift cần periodic retraining
- SSH key-based attacks không cover
- FPR cần cải thiện thêm

---

## CHAPTER 6: CONCLUSION AND FUTURE WORK / KẾT LUẬN (5-7 trang)

### 6.1 Conclusion / Kết luận (2-3 trang)
- Tóm tắt đóng góp chính
- Trả lời research objectives
- IF + dynamic threshold cho phép dự đoán sớm tấn công SSH

### 6.2 Future Work / Hướng phát triển (2-3 trang)
- Deep learning approaches (LSTM, Transformer)
- Multi-protocol support (FTP, RDP)
- Federated detection across multiple servers
- Online learning để xử lý concept drift
- Integration với SOAR platforms

---

## REFERENCES / TÀI LIỆU THAM KHẢO (3-5 trang)

### International Papers (Q1-Q3, 2015-2026, accessible):
1. Liu, F.T. et al. (2008). Isolation Forest. IEEE ICDM
2. Chandola, V. et al. (2009). Anomaly Detection Survey. ACM Computing Surveys
3. Breunig, M. et al. (2000). LOF. ACM SIGMOD
4. Schölkopf, B. et al. (2001). One-Class SVM. Neural Computation
5. Buczak, A. & Guven, E. (2016). Data Mining and ML for Cyber Security IDS. IEEE
6. Ahmad, S. et al. (2021). Network IDS Systematic Study. Sustainability
7. Sperotto, A. et al. (2010). An Overview of IP Flow-Based Intrusion Detection. IEEE
8. Montgomery, D.C. (2019). Statistical Quality Control
9. Lucas, J.M. & Saccucci, M.S. (1990). EWMA Control Charts. Technometrics
10. Ring, M. et al. (2019). A Survey of Network-based Intrusion Detection Data Sets. Computers & Security
11. Maciá-Fernández, G. et al. (2018). UGR'16: A New Dataset for IDS. Computers & Security
12. Pang, G. et al. (2021). Deep Learning for Anomaly Detection: A Review. ACM Computing Surveys
13. Aggarwal, C.C. (2017). Outlier Analysis. Springer
14. Goldstein, M. & Uchida, S. (2016). A Comparative Evaluation of Unsupervised AD Algorithms. PLOS ONE
15. Nassif, A.B. et al. (2021). Machine Learning for Anomaly Detection: A Systematic Review. IEEE Access

### Vietnamese Papers:
16. Nguyễn Văn A. (2022). Ứng dụng ML trong phát hiện xâm nhập. Tạp chí CNTT&TT
17. Trần Văn B. (2023). Phát hiện brute-force bằng deep learning. Hội thảo KHCN FPT
18. Lê Văn C. (2021). Hệ thống phát hiện bất thường mạng. Tạp chí KH&CN ĐHQG

---

## APPENDICES / PHỤ LỤC
- Appendix A: Source code snippets
- Appendix B: Full configuration files
- Appendix C: Additional figures and tables
- Appendix D: Installation guide

---

## PAGE ALLOCATION

| Chapter | Content | Pages |
|---------|---------|-------|
| Abstract | Tóm tắt | 1 |
| Acknowledgement | Lời cảm ơn | 1 |
| Table of Contents | Mục lục | 2 |
| List of Figures/Tables | Danh sách | 2 |
| Abbreviations | Từ viết tắt | 1 |
| Chapter 1 | Introduction | 8-10 |
| Chapter 2 | Literature Review | 15-18 |
| Chapter 3 | Methodology | 18-22 |
| Chapter 4 | Experimental Results | 18-22 |
| Chapter 5 | Discussion | 10-12 |
| Chapter 6 | Conclusion | 5-7 |
| References | Tài liệu tham khảo | 3-5 |
| Appendices | Phụ lục | 5-10 |
| **Total** | | **89-113** |
