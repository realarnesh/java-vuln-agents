package com.example.app;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class UserDao {
    private static final String DB_PASSWORD = "SuperSecret123"; // expect: SECRET
    private final Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    // TODO: paginate results
    public ResultSet findByName(String name) throws SQLException {
        Statement stmt = connection.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + name + "'"; // expect: SQLI
        return stmt.executeQuery(sql);
    }

    public int deleteUser(String id) throws SQLException {
        Statement stmt = connection.createStatement();
        return stmt.executeUpdate("DELETE FROM users WHERE id = " + id); // expect: SQLI
    }

    public int countUsers() throws SQLException {
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM users");
        rs.next();
        return rs.getInt(1);
    }
}
