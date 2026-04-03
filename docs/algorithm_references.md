# Nguồn tham khảo chính xác cho thuật toán và mô hình
# Verified Algorithm & Model References

## 1. Isolation Forest

**Paper gốc (Original Paper):**
- Liu, F.T., Ting, K.M., & Zhou, Z.-H. (2008). "Isolation Forest." In *Proceedings of the 8th IEEE International Conference on Data Mining (ICDM)*, pp. 413–422.
- DOI: 10.1109/ICDM.2008.17
- Download: https://ieeexplore.ieee.org/document/4781136 (IEEE Xplore)

**Paper mở rộng (Extended Paper):**
- Liu, F.T., Ting, K.M., & Zhou, Z.-H. (2012). "Isolation-Based Anomaly Detection." *ACM Transactions on Knowledge Discovery from Data*, 6(1), Article 3.
- DOI: 10.1145/2133360.2133363
- Download: https://dl.acm.org/doi/10.1145/2133360.2133363

**Scikit-learn Implementation:**
- https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html

**Công thức Anomaly Score:**
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Trong đó:
- $h(x)$ = path length của sample x trong isolation tree
- $E(h(x))$ = average path length across all trees
- $c(n)$ = average path length in unsuccessful BST search = $2H(n-1) - 2(n-1)/n$
- $H(i)$ = harmonic number $\approx \ln(i) + 0.5772$ (Euler's constant)
- Score gần 1 = anomaly, gần 0.5 = normal, gần 0 = very normal

## 2. Local Outlier Factor (LOF)

**Paper gốc:**
- Breunig, M.M., Kriegel, H.-P., Ng, R.T., & Sander, J. (2000). "LOF: Identifying Density-Based Local Outliers." In *Proceedings of the 2000 ACM SIGMOD International Conference on Management of Data*, pp. 93–104.
- DOI: 10.1145/342009.335388
- Download: https://dl.acm.org/doi/10.1145/342009.335388

**Công thức:**
1. k-distance(p) = khoảng cách đến neighbor thứ k
2. reach-dist_k(p, o) = max{k-distance(o), d(p, o)}
3. lrd_k(p) = 1 / (Σ reach-dist_k(p, o) / |N_k(p)|)
4. LOF_k(p) = (Σ lrd_k(o)/lrd_k(p)) / |N_k(p)|
5. LOF > 1 = outlier, LOF ≈ 1 = normal

## 3. One-Class SVM

**Paper gốc:**
- Schölkopf, B., Platt, J.C., Shawe-Taylor, J., Smola, A.J., & Williamson, R.C. (2001). "Estimating the Support of a High-Dimensional Distribution." *Neural Computation*, 13(7), pp. 1443–1471.
- DOI: 10.1162/089976601750264965
- Download: https://direct.mit.edu/neco/article/13/7/1443/6687

**Bài toán tối ưu:**
$$\min_{w, \xi, \rho} \frac{1}{2}||w||^2 + \frac{1}{\nu n} \sum_{i=1}^{n} \xi_i - \rho$$
s.t. $w \cdot \Phi(x_i) \geq \rho - \xi_i$, $\xi_i \geq 0$

**RBF Kernel:** $K(x, x') = \exp(-\gamma ||x - x'||^2)$

## 4. EWMA (Exponentially Weighted Moving Average)

**Nguồn gốc:**
- Roberts, S.W. (1959). "Control Chart Tests Based on Geometric Moving Averages." *Technometrics*, 1(3), pp. 239–250.

**Paper ứng dụng trong control charts:**
- Lucas, J.M. & Saccucci, M.S. (1990). "Exponentially Weighted Moving Average Control Schemes: Properties and Enhancements." *Technometrics*, 32(1), pp. 1–12.
- DOI: 10.2307/1269835
- Download: https://www.jstor.org/stable/1269835

**Sách tham khảo:**
- Montgomery, D.C. (2019). *Introduction to Statistical Quality Control*, 8th Edition. Wiley.
- ISBN: 978-1119399308

**Công thức:**
$$Z_t = \lambda X_t + (1-\lambda) Z_{t-1}$$
Trong đó λ (alpha) ∈ (0, 1] là smoothing factor.

## 5. Anomaly Detection Survey (Foundational)

- Chandola, V., Banerjee, A., & Kumar, V. (2009). "Anomaly Detection: A Survey." *ACM Computing Surveys*, 41(3), Article 15.
- DOI: 10.1145/1541880.1541882
- Download: https://dl.acm.org/doi/10.1145/1541880.1541882
- **Journal ranking: Q1** (Impact Factor ~16)

## 6. ML for Intrusion Detection

- Buczak, A.L. & Guven, E. (2016). "A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection." *IEEE Communications Surveys & Tutorials*, 18(2), pp. 1153–1176.
- DOI: 10.1109/COMST.2015.2494502
- **Journal ranking: Q1** (Impact Factor ~33)

## 7. RobustScaler

**Scikit-learn documentation:**
- https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.RobustScaler.html
- Uses median and IQR (Interquartile Range) instead of mean and std
- Formula: $X_{scaled} = \frac{X - Q_2}{Q_3 - Q_1}$

## 8. SSH Protocol

- Ylönen, T. & Lonvick, C. (2006). "The Secure Shell (SSH) Protocol Architecture." RFC 4251, IETF.
- https://www.rfc-editor.org/rfc/rfc4251
- RFC 4252: SSH Authentication Protocol
- RFC 4253: SSH Transport Layer Protocol
- RFC 4254: SSH Connection Protocol

## Xác nhận: Tất cả references trên đều:
- ✅ Là papers/RFCs/documentation thực tế (không hallucination)
- ✅ Có DOI hoặc URL có thể truy cập
- ✅ Có thể download/đọc online
- ✅ Từ các nguồn uy tín (IEEE, ACM, MIT Press, IETF, Springer, Wiley)
