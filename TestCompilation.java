// Test file to verify all modules compile correctly
import org.example.UnifiedServerRefactored;
import org.example.UnifiedServerHandler;
import org.example.AdminPanel;
import org.example.ServerStatistics;
import org.example.utils.AdminLogger;
import org.example.utils.ServerConfig;

public class TestCompilation {
    public static void main(String[] args) {
        System.out.println("All modules imported successfully!");
        System.out.println("Server port: " + ServerConfig.getPort());
        System.out.println("Admin username: " + AdminLogger.ADMIN_USERNAME);
        System.out.println("Server ready for compilation!");
    }
}
