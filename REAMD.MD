# Hệ Thống Quản Lý Bán Hàng

## Giới thiệu

**Hệ Thống Quản Lý Bán Hàng** là một ứng dụng web được xây dựng bằng Node.js, Express và MySQL. Ứng dụng hỗ trợ các chức năng chính sau:

- **Xác thực người dùng:** Đăng ký và đăng nhập với bảo mật bằng JWT và bcrypt.
- **Quản lý sản phẩm:** Thực hiện các thao tác CRUD (tạo, đọc, cập nhật, xóa) cho sản phẩm, kèm theo chức năng tìm kiếm theo tên và mô tả.
- **Quản lý đơn hàng:** Tạo, cập nhật trạng thái, xem và xóa đơn hàng.

Dự án này được thiết kế cho các doanh nghiệp vừa và nhỏ nhằm tối ưu hóa quy trình bán hàng và quản lý tồn kho.

## Công nghệ sử dụng

- **Backend:** Node.js, Express, MySQL, JWT, bcrypt.
- **Frontend:** HTML, CSS, Bootstrap.
- **Cơ sở dữ liệu:** MySQL.

## Cài đặt

### Yêu cầu

- Node.js (phiên bản 14 trở lên)
- MySQL

### Hướng dẫn cài đặt

1. **Clone dự án:**

   ```bash
   git clone https://github.com/phanvanphat/sales-management.git
   cd sales-management
