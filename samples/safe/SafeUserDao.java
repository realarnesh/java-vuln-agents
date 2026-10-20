package com.example.app;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SafeUserDao {
    private final String dbPassword = System.getenv("DB_PASSWORD");
    private final Connection connection;

    public SafeUserDao(Connection connection) {
        this.connection = connection;
    }

    public ResultSet findByName(String name) throws SQLException {
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, name);
        return stmt.executeQuery();
    }
}
