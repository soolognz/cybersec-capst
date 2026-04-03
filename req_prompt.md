Chủ đề: Đồ án/khóa luận tốt nghiệp Đại học chuyên ngành An toàn thông tin. Đề tài khóa luận tốt nghiệp là Ứng dụng AI trong phát hiện và phòng chống tấn công Brute-force trên hệ thống
SSH với dự đoán sớm (Application of AI in Detecting and Preventing Brute-Force Attacks on SSH Systems with Early Prediction)

Hãy phân tích chi tiết file capstone.pdf trong thư mục hiện tại, đây chính là proposal đồ án tốt nghiệp của tôi. Sau khi phân tích chi tiết, chính xác, đầy đủ, hãy thực hiện lên bản kế hoạch (plan) chi tiết cho dự án quan trọng này. Sau đó, thực hiện triển khai toàn bộ dự án (thiết kế cấu trúc hệ thống (design system) - cấu trúc dự án, workflow, code, training, documents, thesis reports, quy trình hoạt động, etc.) hoàn chỉnh, logic, đầy đủ, chính xác, đạt yêu cầu, được đánh giá cao trước hội đồng, đạt điểm tối đa trên thang điểm 10.

Tất cả các tasks, plan, tài liệu, quy trình... đều phải được lưu trữ vào một thư mục riêng của dự án để tôi có thể kiểm tra, và bạn cũng dùng nó để nắm bắt và hiểu để phục vụ cho các session khác nhau (tách biệt với cấu trúc thư mục dự án).

## Documents and Thesis Report (Very Important)
- Sau khi phân tích và lên plan, hãy đưa ra những gợi ý về các luận điểm, dàn ý, ý chính, thông tin, nội dung cần thiết và quan trọng chi tiết, logic, rõ ràng, chuyên nghiệp, chuẩn xác, đủ ý, đạt điểm tối đa (thang điểm 10) cho từng phần của thesis report (luận văn báo cáo khóa luận tốt nghiệp). Hãy tham khảo tất các bài báo nghiên cứu khoa học, bài báo nghiên cứu chuyên ngành, tạp chí journals, research, bài viết articles, blogs, conferences,… uy tín, đáng tin cậy, chất lượng, rank Q1 - Q3 phù hợp và liên quan đến đề tài khóa luận tốt nghiệp/đồ án tốt nghiệp của tôi. 

- Các bài báo nghiên cứu khoa học, tạp chí, bài viết, blog phải bao gồm cả quốc tế và Việt Nam.

- Tìm kiếm tất cả các bài báo nghiên cứu khoa học, nghiên cứu chuyên ngành, bài viết articles, tạp chí journals, blog,… hỗ trợ để viết khóa luật tốt nghiệp/đồ án tốt nghiệp đầy đủ, logic, chính xác, chuyên nghiệp. Đưa ra dàn ý, luận điểm, ý chính cùng với các dẫn chứng chứng minh cho từng luận điểm, ý chính đó. 

- Phân tích file Research_Based_Thesis.docx và xây dựng cấu trúc và outline báo cáo khóa luận tốt nghiệp (thesis report structure) hoàn chỉnh, logic, đầy đủ giống trong file đã cung cấp. Sau đó triển khai viết bài hoàn chỉnh, tránh đạo văn (avoid plagiarism).

- Trình bày rõ ràng, văn phong chuyên nghiệp, xuất ra .docx hoặc .md. Ngôn ngữ gồm 2 bản tiếng Việt và tiếng Anh. Có dẫn chứng chứng minh.

- Số trang yêu cầu là trên 85 trang cho toàn bộ thesis reprot. Do đó, hãy đưa ra càng chi tiết càng tốt.

- Hãy đảm bảo số papers trong khoảng 2015 - 2026 chiếm tỷ lệ 65% - 75% của toàn bộ khóa luận. Có thể truy cập (accessible, open access,…), có thể download. Không dùng các paper mà tôi không thể đọc, không thể truy cập hay không thể download. 

- Đảm bảo thesis report và documents phải match với tất cả các thành phần của dự án. Phải thống nhất, nhất quán, đồng bộ, chung một nội dung, chủ đề.

## Project Implementation (Very important)
- Đưa ra plan và quy trình thực hiện chi tiết, logic, chính xác. Sau đó, dựa vào plan và quy trình để triển khai.

- Thực hiện hướng dẫn và cài đặt, set up toàn bộ hệ thống, công cụ cần thiết một cách chi tiết, chính xác, đầy đủ, logic (bao gồm cả thủ công manual, docker,...)

- Thực hiện đưa ra quy trình tiền xử lý và xử lí dataset logic, đầy đủ, thống nhất, hoàn chỉnh, chuẩn xác. Phải có dẫn chứng chứng minh từ các nghiên cứu về các bước, quy trình xử lí dữ liệu và trích xuất đặc trưng. Phải phù hợp với cả 3 mô hình được chọn gồm Isolation Forest (main model), LOF (benchmark), One-Class SVM (benchmark).
    - Dataset bao gồm file honeypot_auth.log và simulation_auth.log được lưu trữ trong thư mục /Dataset. 
        - File honeypot_auth.log là log được lấy từ server vps của tôi (chứa toàn log đã ssh thành công bằng user root và phần còn lại nhiều nhất – những phần thất bại tất cả đều là log do attacker thật tấn công vào thông qua nhiều kỹ thuật khác nhau). Và phải tách biệt riêng giữa file train và file test ra riêng, đồng thời thống kê rõ số lượng log dùng để train và test là bao nhiêu cho đúng. Nhiệm vụ của bạn là xử lý log, gán nhãn dữ liệu. Trong đó, dữ liệu được gán nhãn như sau: File log ở honeypot_auth.log chứa cả normal và anormal (tách hết phần normal ra, phần normal là phần đăng nhập thành công bằng user root),còn phần còn lại thì gán nhãn là attack hoặc anomally. 

        - File log ở simulation_auth.log chứa toàn log của hành vi người dùng bình thường nên hãy gán nhãn nó là normal. 70% dùng để train và 30% dùng để test

        - Bộ dữ liệu train hoàn toàn bằng simulation_auth.log. Bộ dữ liệu test dùng 30% dữ liệu được tách ra trong simulation_auth.log kết hợp với honeypot_auth.log tạo thành bộ dữ liệu test hoàn chỉnh với tỉ lệ normal:attack là 1:3. 

- Các features phải được trích xuất chính xác, đầy đủ, phù hợp với cả 3 model là IF, LOF, OCSVM. Số lượng features phải >= 10. Đưa ra xếp hạng những features quan trọng nhất, hữu ích nhất, có tác dụng đối với mô hình và dự án. Tât cả các features phải dùng được cho cả 3 model để việc so sánh các mô hình đạt được độ chính xác, tin cậy cao, thuyết phục. Thực hiện nghiên cứu cách trích xuất đặc trưng chuẩn, tốt nhất để thực hiện xử lí và train model được chính xác, đạt kết quả cao nhất có thể.

- Thực hiện train model phải dựa vào các thuật toán đạt độ chính xác cao, uy tín, đáng tin cậy, có nghiên cứu chứng minh.

- So sánh mô hình về tất cả các mặt và khía cạnh như performance metrics, training, sự phù hợp của mô hình đối với dự án và hệ thống phát hiện cảnh báo dự đoán sớm tấn công SSH sử dụng dynamic threshold,... (nghiêng về Isolation Forest)

- Dynamic Threshold:
    - Thực hiện deep research từ các các bài báo nghiên cứu khoa học, nghiên cứu chuyên ngành, bài viết, tạp chí, blog uy tín và sau đó thiết kế và kết hợp các thuật toán thành một thuật toán tối ưu, hiệu quả cho bài toán và vấn đề của dự án này của tôi.

    - Phải có dẫn chứng cho các thuật toán, cách kết hợp, lí do có thể kết hợp để đạt được sự tối ưu, hiệu quả, sát với thực tế.

    - Phải kết hợp các thuật toán tối ưu nhất, linh hoạt nhất, mạnh mẽ nhất để hệ thống vận hành mượt mà, trơn tru, đáp ứng kì vọng của đồ án, đồng thời áp dụng thực tế và production.

- Visualization:
    - Thiết kế web monitor dashboard tích hợp Kibana Dashboard và ELK Stack vào để hiển thị trực quan real-time hệ thống vận hành hoạt động (như một hệ thống thực).

- Alert and Prevention Module:
    - Tạo cảnh báo cho các cuộc tấn công đã phát hiện và dự đoán. Cảnh báo bắn về email của admin system và cảnh báo xuất hiện trên web hệ thống (đã thiết kế ở trên)
    - Tích hợp với Fail2Ban để tự động chặn các địa chỉ IP độc hại.

- Dự án, hệ thống phải có thể triển khai real-time trên các môi trường lab, production, thực tế mà không gặp vấn đề gì. Tôi cần phải demo real-time trước hội đồng nên cần phải được đánh giá cao, sát như môi trường thực tế

- Tất cả các bước làm và quy trình đều phải được viết thành documents, diễn giải logic, chi tiết, chuẩn xác

- Dự án phải được triển khai demo thực tế, do đó cần phải được thực hiện sát với thực tế nhất có thể.

- Đưa ra đầy đủ các kịch bản tấn công có thể thực hiện được (có cả demo). Viết tools giả lập tấn công như thật. Tái hiện thực tế (real-world) được càng tốt.
## Additional Requirements
- Tất cả các phần, từ thesis report đế implementation đều phải có các dẫn chứng chứng minh uy tín, đáng tin cậy từ các bài báo nghiên cứu khoa học, nghiên cứu chuyên ngành, bài viết, tạp chí, blog uy tín, được xác thực.

- Toàn bộ dự án phải thống nhất, đồng bộ, nhất quán với nhau. 

- Sau khi hoàn thành xong hết tất cả mọi thứ, vui lòng xuất ra file hướng dẫn cách setup manual từng bước một bằng file .docx cho đến khi hoàn thành để tôi có thể đưa vào báo cáo đồ án và người dùng khác có thể dựa vào nó và setup hệ thống tương tự như của tôi.

- Thực hiện đẩy lên github của tôi và thực hiện bảo mật repo theo tiêu chuẩn.

- Sử dụng tât cả các skills trong folder .claude phù hợp với dự án.

- Không lan man, không đi lệch khỏi dự án.

- Khóa luận tốt nghiệp/đồ án này rất quan trọng nên phần thesis report và triển khai thực tế phải đồng bộ, nhất quán, match nhau.

- Đóng gói toàn bộ dự án vào docker (nếu có thể), bao gồm cả triển khai lẫn giả lập tấn công. Vì dự án của nhóm tôi buộc phải có trên máy cá nhân mỗi người, mỗi người đều phải có thể chạy được dự án.