---
title: "KHÓA LUẬN TỐT NGHIỆP: Ứng dụng AI trong phát hiện và phòng chống tấn công Brute-force trên hệ thống SSH với dự đoán sớm"
author: "Trường Đại học FPT — Chuyên ngành An toàn thông tin"
date: "Hà Nội, 2026"
---

\newpage

# LỜI CẢM ƠN {-}

Lời đầu tiên, nhóm chúng em xin gửi lời cảm ơn chân thành và sâu sắc nhất đến giảng viên hướng dẫn đã tận tình chỉ bảo, định hướng và hỗ trợ nhóm trong suốt quá trình thực hiện khóa luận tốt nghiệp.

Chúng em xin cảm ơn Ban Giám hiệu Trường Đại học FPT, Khoa Công nghệ Thông tin và các thầy cô trong chuyên ngành An toàn thông tin đã tạo điều kiện thuận lợi cho chúng em học tập và nghiên cứu.

Chúng em cũng xin gửi lời cảm ơn đến gia đình, bạn bè và các thành viên trong nhóm đã luôn động viên, hỗ trợ và đóng góp ý kiến quý báu trong quá trình thực hiện đề tài.

Mặc dù nhóm đã nỗ lực hết sức, khóa luận không tránh khỏi những thiếu sót. Nhóm rất mong nhận được sự góp ý từ quý thầy cô và Hội đồng để hoàn thiện hơn.

\begin{flushright}
\textit{Hà Nội, tháng 4 năm 2026}\\
\textit{Nhóm sinh viên thực hiện}
\end{flushright}

\newpage

# TÓM TẮT {-}

Tấn công brute-force SSH là một trong những mối đe dọa phổ biến và dai dẳng nhất trong lĩnh vực an ninh mạng. Các công cụ phòng chống truyền thống như Fail2Ban hoạt động dựa trên ngưỡng tĩnh, chỉ phản ứng sau khi tấn công đã xảy ra và dễ bị lẩn tránh bởi các kỹ thuật tấn công tiên tiến như low-and-slow hoặc distributed brute-force.

Khóa luận này trình bày việc thiết kế, triển khai và đánh giá một hệ thống phát hiện và phòng chống tấn công brute-force SSH sử dụng trí tuệ nhân tạo, với khả năng dự đoán sớm (early prediction). Hệ thống sử dụng thuật toán Isolation Forest làm mô hình phát hiện bất thường chính, kết hợp với cơ chế ngưỡng động EWMA-Adaptive Percentile để cung cấp khả năng cảnh báo sớm hai mức (EARLY_WARNING và ALERT).

Bộ dữ liệu nghiên cứu gồm 174.250 dòng nhật ký SSH, bao gồm dữ liệu tấn công thực tế từ hệ thống honeypot (119.729 dòng, 679 địa chỉ IP) và dữ liệu hành vi bình thường (54.521 dòng, 64 người dùng). Hệ thống trích xuất 14 đặc trưng hành vi theo cửa sổ thời gian 5 phút cho mỗi địa chỉ IP nguồn.

Kết quả: Isolation Forest đạt F1-Score 93,74%, Accuracy 90,31%, FPR 29,00% sau tối ưu. So sánh với LOF (F1=89,94%) và One-Class SVM (F1=94,55%), IF được chọn nhờ khả năng tạo anomaly score phù hợp cho thuật toán ngưỡng động. Hệ thống được triển khai hoàn chỉnh với Docker Compose (9 services), bao gồm FastAPI backend, React dashboard, ELK Stack, Fail2Ban và pipeline phát hiện thời gian thực.

**Từ khóa:** SSH, brute-force, phát hiện bất thường, Isolation Forest, ngưỡng động, EWMA, dự đoán sớm, học máy, ELK Stack, Fail2Ban.

\newpage

# ABSTRACT {-}

SSH brute-force attacks remain one of the most prevalent and persistent threats in cybersecurity. Traditional defense tools such as Fail2Ban operate on static thresholds, reacting only after an attack has occurred and being easily evaded by advanced techniques such as low-and-slow or distributed brute-force attacks.

This thesis presents the design, implementation, and evaluation of an AI-powered system for detecting and preventing SSH brute-force attacks with early prediction capability. The system employs Isolation Forest as the primary anomaly detection model, combined with an EWMA-Adaptive Percentile dynamic threshold mechanism to provide two-level early warnings.

The research dataset comprises 174,250 SSH log entries from a honeypot system (119,729 lines, 679 attacking IPs) and simulated normal behavior (54,521 lines, 64 users). The system extracts 14 behavioral features per 5-minute window per source IP.

Results: Isolation Forest achieves F1-Score of 93.74%, Accuracy of 90.31%, and FPR of 29.00% after optimization. The complete system is deployed as a Docker Compose stack with 9 services including real-time detection, FastAPI backend, React dashboard, ELK Stack visualization, and Fail2Ban integration.

**Keywords:** SSH, brute-force, anomaly detection, Isolation Forest, dynamic threshold, EWMA, early prediction, machine learning, ELK Stack, Fail2Ban.

\newpage
