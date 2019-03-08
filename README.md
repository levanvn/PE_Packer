# Writing a simple PE Packer in detail 

Packers là một trong những kỹ thuật anti-RE rất phổ biến được sử dụng. Packer có nhiều lợi ích như làm rối mã nguồn tạo ra độ khó và kỹ năng cho người phân tích, giảm thiểu kích thước file thực thi lưu trữ trên bộ nhớ và có thể ẩn mình trước những phần mềm antivirus. Bài viết sẽ trình bày về nguyên lý mà các chương trình packer vẫn thường sử dụng và đi sâu vào những chi tiết kỹ thuật để hoàn thành được một chương trình Packer đầy đủ.
Ý tưởng ban đầu của việc Packer là nén/ mã hóa đoạn code hoặc toàn bộ phân đoạn trong PE file, sau đó một đoạn mã giải nén thực thi trong thời gian chạy sẽ giải mã và thực thi mã nguyên thủy. 
 
 ![0](https://user-images.githubusercontent.com/39437600/54019608-2f9e3580-41be-11e9-95b2-05ca846c1fd5.png)

Như hình trên, file sau khi packing sẽ chứa 2 section, một là phần dữ liệu đã bị packed và một là đoạn unpacker code (Stub).  New OEP ở Stub sẽ bắt đầu việc giải nén section thứ nhất, kết thúc Stub là một cú nhảy đuôi (Tail Jump) sẽ nhảy đến OEP ban đầu và chương trình gốc sẽ được thực thi.

Một vấn đề khó khăn mà chúng ta gặp phải trong việc xây dựng một trình Packer là động chạm đến những metadata ( hầu hết nằm trong PE Header). Những siêu dữ liệu này được dùng cho hệ thống Windows và Loader khi load file vào bộ nhớ. PE file có 16 Data Directoris đồng nghĩa với việc chúng ta phải packed và resolving 16 phần và mỗi phần đều liên quan mật thiết đến việc quản lý của Windows mà nhiều cái trong đó đều undocument bởi Microsofts.  Chúng  ta có thể tham khảo mã nguồn mở upx để xem cách họ xử lý đối với từng phần, nhưng upx được viết cho nhiều nền tảng và khó đọc. Ở bài viết này chỉ đề cập tới một vài phần thường được sử dụng nhiều nhất như là xử lý import, export, tls section, resource section.

Một vấn đề khác là khi viết code cho đoạn Unpacking Stub là chúng ta cần viết shellcode bằng asm hoặc viết bằng C/C++ rồi biên dịch ra asm. Trong bài sẽ hướng dẫn sử dụng Visual Studio để biên dịch C ra shellcode.

Một điều quan trọng nữa là chúng ta sẽ sử dụng trình nén hoặc mã hóa nào để che dấu dữ liệu. Trong bài sẽ sử dụng phép XOR đơn giản theo chế độ CBC để mã hóa. Vì sử dụng phép XOR nên kích thước file sau packed còn lớn hơn file ban đầu vì phải chứa thêm thông tin giải nén. Mục đích của packer này không phải là giảm kích cỡ lưu file mà là tìm hiểu cách xây dựng một trình Packer đơn giản.

Right, bây giờ chúng ta bắt đầu viết một PE Packer.
Đầu tiên, viết một hàm mã hóa và giải mã 

 ![1](https://user-images.githubusercontent.com/39437600/54019037-c23dd500-41bc-11e9-8d90-2edbaa38484f.PNG)

Đầu vào là một con trỏ đến mảng dữ liệu và kích thước của nó. Một mảng a được fix cứng để phục vụ cho mã hóa.
Đã có hàm mã hóa, bây giờ chúng ta định nghĩa một số thông tin cho việc unpacking sau này

 ![2](https://user-images.githubusercontent.com/39437600/54019199-2e203d80-41bd-11e9-88b7-22532b6d3dfd.PNG)

Ở đây có một việc cần lưu ý, là thông tin cần để unpacking còn nhiêu hơn thế này, hình trên chỉ để cập đến import directories, mà chưa có đến các phần khác (Resource, TLS ,…),  biết viết sẽ trình bày chiến lược để giải quyết từng phần, mà trước hết là phần Import directory.

Một cách tổng thể file sau khi có packed sẽ có PE Header và 2 section như hình trên đã minh họa ( Packed original data và Unpacking Stub). PE Header sẽ điều chỉnh một số thứ trong quá trình làm. Bây giờ chúng ta thiết kế section thứ nhất. 

Phần này chứa 3 thông tin cơ bản theo thứ tự: đầu tiên là cấu trúc được định nghĩa ở trên để phục vụ cho unpacking (1), tiếp theo là phần raw data của tất cả section của file nguyên thủy (2), phần cuối là không gian cho phần Import (3).

Ở (1) và (2) khá dễ dàng, chúng ta viết viết một trình đọc cấu trúc PE file để điền vào 2 khối thông tin đầu tiên của cấu trúc packed_file_infor ở trên (khôi cuối sẽ được điền vào khi xử lý phần (3) ). Ở phần (2) chúng ta duyệt qua từng section trong file ban đầu, dữ liệu chúng ta cần lấy là cả section header (cho việc phân bổ bộ nhớ sau này) và section raw data. Dùng hàm XOR đã viết ở trên để mã hóa dữ liệu ở phần (2) này. 

Sang phần 3, những hàm được Import sẽ gợi ý đến chức năng mà chương trình  thực hiện, nên chúng ta packed chúng và chỉ sử dụng 2 hàm là LoadLibrary và GetProcessAddress mà thôi. Từ 2 hàm này chúng ta sẽ tìm cách khôi phục lại các hàm import ban đầu. Nhắc lại về Import Directories trong PE file. Đại khái, khi chúng ta thực hiện một lời gọi hàm thư viện, ví dụ call ExitProcess, thì trình biên dịch sẽ gom tất cả các hàm trong cùng một thư viện đặt tại một cấu trúc gọi là IAT, trên đĩa IAT sẽ lưu một con trỏ đến tên của hàm. Mỗi khi file được load lên bộ nhớ, thì trình loader sẽ lấp đầy bảng IAT bằng địa chỉ thực sự của hàm chứ không phải là một con trỏ đến tên hàm nữa. Bằng cách là dùng hàm GetProcessAddress(handle, name) để lấy địa chỉ thực trong export section. Khi đó call ExitProcess sẽ tham chiếu đến ô nhớ IAT chứa địa chỉ thực của ExitProcess.

Ở đây phần unpacking stub sẽ làm việc mà Loader vẫn làm khi load file vào bộ nhớ.

Trở lại công việc ở (3) chúng ta cần xây dựng một Import Directories mà chứa 2 hàm là LoadLibrary và GetProcessAddress của thư viện Kernel32.dll, để phục vụ cho việc khôi phục bảng IAT sau này.
 
 ![3](https://user-images.githubusercontent.com/39437600/54019217-3ed0b380-41bd-11e9-8f90-343f730a1e89.PNG)

Những việc cần làm là:
1.	Viết 3 chuỗi là tên thư viện, hàm vào không gian địa chỉ này, để cho directory trở tới
2.	Ở PE Header, Chỉnh sửa Import Directory RVA  là RVA của phần (3) này
3.	Ở phần Import Directory chỉnh sửa Name RVA là RVA của string “kernel32.dll”.
4.	Phần không gian cho bảng IAT chúng ta đã để dành ngay từ đầu. Đó là 3 DWORD cuôi của cấu trúc (1).  FirstThunk ở Import Directory phải trỏ đến RVA của DWORD đầu tiên.
5.	Điền RVA của string LoadLibrary vào DWORD thứ nhất, RVA của string GetProcessAddress vào DWORD thứ 2. Khi được nạp vào bộ nhớ, Loader sẽ điền địa chỉ thực của 2 hàm trên vào 2 DWORD này.
6.	DWORD cuối cùng chúng ta phải điền 0 vào, như là dấu hiệu để báo kết thúc bảng IAT.

Done! Ở Section này chúng ta chú ý để  Vitual size  trong section header là một không gian đủ chứa  dữ liệu sau khi giải nén, bởi nếu dùng phép nén thật thì dữ liệu sẽ bung ra rất nhiều, còn các trường khác trong section header chúng ta để theo logic của section. Bây giờ chuyển sang Section Unpacking Stub.

Unpacking Stub này làm một số công việc:

1.	Giải mã Data đã mã hóa ở Section đầu tiên, data ở đây bao gồm section header và section raw data của các section nguyên thủy
2.	Từ thông tin trong section header vừa giải mã, copy Raw data trong mỗi section đến Vitual Adrress mà section header đã chỉ ra cho mỗi section.
3.	Lấp đầy bảng IAT ban đầu bằng địa chỉ thực của hàm, địa chỉ này lấy bằng 2 hàm LoadLibrary và GetProcessAddress mà chúng ta đã thực hiện ở trên.
4.	Nhảy về địa chỉ OEP ban đầu. OEP cũng đã được lưu trong struct ở Section đầu tiên.

Như đã nói ở trên, Stub này viết bằng asm hoặc bằng C rồi bên dịch ra shellcode. Ở đây sẽ dùng Visual Studio để biên dịch ra shellcode 
 
 ![4](https://user-images.githubusercontent.com/39437600/54019275-5a3bbe80-41bd-11e9-8f99-b8a260de83be.PNG)
 
Tạo hàm unpack_main() có kiểu __declspec(naked), kiểu naked sẽ chỉ cho trình biên dịch rằng phần đầu mào của hàm sẽ được tạo thủ công, ở hình trên chúng ta trừ esp đi 256 byte, đủ chỗ cho các biến local.
 ![5](https://user-images.githubusercontent.com/39437600/54019300-73446f80-41bd-11e9-86a0-cb6ba0b7a943.PNG)

Ở cuối hàm ta không có đoạn epilogue như thông thường mà là một cú nhảy đên OEP ban đầu. Trong cửa sổ Property của Project, trong phần Linker, chọn Entry Point là tên hàm unpack_main(), sau đó biên dịch, ta có một file shellcode là dữ liệu cho phần Section Unpacking Stub.

Đến đây, có thể Packing được những file .exe không chứa phần resource, tls.

Trong phần sau sẽ trình bày về cách xây dựng lại các phần export, tls, resource. 


 





