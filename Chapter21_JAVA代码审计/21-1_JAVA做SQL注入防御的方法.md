### JAVA 在做 SQL 注入防御时有哪些方法

**1. 使用预处理语句**

这是 Java 中防御 SQL 注入最主要、最安全的方法。它与数据库通信时，会先发送 SQL 语句的模板，数据库编译好后，再将用户数据作为参数发送。这样，数据库只将数据视为数据，不会当作可执行的 SQL 命令

**JDBC 示例**

```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class UserDAO {
    
    public void getUserData(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/testdb", "user", "password");
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            // 1. 设置参数，将用户输入绑定到占位符
            pstmt.setString(1, username);
            
            // 2. 执行查询
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    System.out.println("User found: " + rs.getString("username"));
                } else {
                    System.out.println("User not found.");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
```

- **核心:** 使用 `?` 作为占位符，然后通过 `pstmt.setString()`、`pstmt.setInt()` 等方法将用户输入绑定到这些占位符上

**2. 使用 ORM 框架**

如果你使用 Java 生态系统中的主流框架，如 Spring Boot、Hibernate、MyBatis，那么 ORM 是首选。这些框架将面向对象编程与关系型数据库操作结合起来，从根本上消除了手动编写 SQL 的需要，从而自动防御 SQL 注入

**Hibernate 示例**

```java
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;
import com.example.model.User;

public class UserRepository {
    
    private final SessionFactory sessionFactory;
    
    public User findByUsername(String username) {
        try (Session session = sessionFactory.openSession()) {
            // HQL (Hibernate Query Language) 示例
            // Hibernate 会自动处理参数绑定
            Query<User> query = session.createQuery("from User where username = :username", User.class);
            query.setParameter("username", username);
            
            return query.uniqueResult();
        }
    }
}
```

- **核心:** Hibernate 等 ORM 框架在底层使用预处理语句来执行所有数据库操作，因此你不需要担心 SQL 注入问题

**3. 最小权限原则**

这是一个重要的安全实践

- **不要使用数据库的管理员账户**（如 `root`）来运行应用程序
- 为你的应用程序**创建专用的数据库用户**，并只授予其完成任务所需的最小权限。例如，一个只进行读取操作的服务，其数据库用户就应该只有 `SELECT` 权限

| 防御方法   | 优点                                            | 缺点                                     | 推荐度                 |
| ---------- | ----------------------------------------------- | ---------------------------------------- | ---------------------- |
| 预处理语句 | 最安全、最彻底的防御；将数据与SQL代码分离。     | 需要手动编写SQL，语法略显繁琐。          | 最高                   |
| ORM框架    | 从根本上杜绝SQL注入；开发效率高；代码可读性好。 | 需要学习框架；不适用于简单或无框架项目。 | 非常高                 |
| 最小权限   | 降低攻击后的危害。                              | 无法从根本上防御注入。                   | 非常高（作为安全原则） |