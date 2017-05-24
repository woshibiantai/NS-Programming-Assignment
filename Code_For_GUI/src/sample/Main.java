package sample;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.io.File;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.Arrays;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;


public class Main extends Application{

    Stage window;
    Scene mainMenu;
    Scene serverMenu;
    Scene clientMenu;
    Scene serverOperation;
    Scene clientOperation;

    //Main Menu buttons
    Button selectServerButton;
    Button selectClientButton;

    //Server Menu Buttons
    Button serverBackButton;
    Button serverStartButton;
    Button serverPrivateKeyButton;
    Button serverCertificateButton;

    //ServerOperation Buttons
    Button serverQuitButton;

    //Client Menu Buttons
    Button clientBackButton;
    Button clientCertificateButton;
    Button clientDataButton;
    Button clientStartButton;

    //ClientOperation Buttons
    Button clientQuitButton;

    Label label1;
    Label serverIPAddress;
    Label clientStatus;

    //Server File Choosers
    FileChooser privateKeySelect;
    FileChooser serverCertificateSelect;

    //Client File Choosers
    FileChooser caCertificateSelect;
    FileChooser dataSelect;
    TextField ipAddressSelect;


    ComboBox serverHashAlgorithmSelect;

    ListView<String> list;





    ExecutorService executorService = Executors.newCachedThreadPool();

    UpdateListTask updateListTask = new UpdateListTask();

    @Override
    public void start(Stage primaryStage) throws Exception{

        window = primaryStage;

        label1 = new Label("Select client or server:");

//        Parent root = FXMLLoader.load(getClass().getResource("/Users/jonathanbeiqiyang/IdeaProjects/NS_GUI/src/sample/sample.fxml"));

        primaryStage.setTitle("NS Program"); //Title of the window

        /**
         * Setup for Main Menu Scene
         */
        selectServerButton = new Button("Server");
        selectClientButton = new Button("Client");

        clientBackButton = new Button("back to Main Menu");


        selectServerButton.setOnAction(e -> window.setScene(serverMenu));
        selectClientButton.setOnAction(e -> window.setScene(clientMenu));

        VBox mainMenuLayout = new VBox(20); //main layout to add elements into
        mainMenuLayout.getChildren().addAll(label1, selectServerButton, selectClientButton);

        mainMenu = new Scene(mainMenuLayout, 500,400);

        /**
         * Setup for Server Menu Scene
         */
        String[] serverArguments = {"/Users/jonathanbeiqiyang/IdeaProjects/NS_GUI/NS Programming Assigment/src/privateServer.der",
                "/Users/jonathanbeiqiyang/IdeaProjects/NS_GUI/NS Programming Assigment/src/1001619.crt", "MD5"};

        String[] clientArguments = {"/Users/jonathanbeiqiyang/IdeaProjects/NS_GUI/NS Programming Assigment/src/CA.crt",
        "/Users/jonathanbeiqiyang/IdeaProjects/NS_GUI/NS Programming Assigment/src/sampleData/largeFile.txt", "000.000.0.000"};


        serverBackButton = new Button("back to Main Menu");
        serverStartButton = new Button("Start Server!");
        serverPrivateKeyButton = new Button("Set private key file");
        serverCertificateButton = new Button("Set Server certificate file");

        privateKeySelect = new FileChooser();
        privateKeySelect.setTitle("Select private key (.der format)");
        serverCertificateSelect = new FileChooser();
        serverCertificateSelect.setTitle("Set Server certificate file");

        ObservableList<String> hashingAlgoOptions =
                FXCollections.observableArrayList(
                        "MD5"
                );
        serverHashAlgorithmSelect = new ComboBox(hashingAlgoOptions);



        serverBackButton.setOnAction(e -> window.setScene(mainMenu));
        serverStartButton.setOnAction(e -> {

            Task serverBackgroundTask = new Task() {
                @Override
                protected Object call() throws Exception {
                    return null;
                }

                @Override
                public void run(){
                    ServerCP2 serverCP2 = new ServerCP2();


                    try {
                        serverCP2.main(serverArguments);

                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }
                }
            };
            executorService.submit(serverBackgroundTask);
            window.setScene(serverOperation);


        });
        serverPrivateKeyButton.setOnAction(e -> {
            File privateKeyFile = privateKeySelect.showOpenDialog(window);
            serverArguments[0] = privateKeyFile.getAbsolutePath();
            System.out.println(serverArguments[0]);
        });
        serverCertificateButton.setOnAction(e -> {
            File serverCertificate = serverCertificateSelect.showOpenDialog(window);
            serverArguments[1] = serverCertificate.getAbsolutePath();
            System.out.println(serverArguments[1]);
        });
        serverHashAlgorithmSelect.valueProperty().addListener(new ChangeListener() {
            @Override
            public void changed(ObservableValue observable, Object oldValue, Object newValue) {
                serverArguments[2] =  newValue.toString();
                System.out.println(serverArguments[2]);
            }
        });

        VBox serverMenuLayout = new VBox(20);
        serverMenuLayout.getChildren().addAll(serverPrivateKeyButton, serverCertificateButton, serverHashAlgorithmSelect, serverStartButton,
                serverBackButton);


        serverMenu = new Scene(serverMenuLayout, 500, 400);

        /**
         * Setup for client Menu Scene
         */
        clientCertificateButton = new Button("Select CA Certificate");
        clientDataButton = new Button("Select Data to be sent");
        clientStartButton = new Button("Start Client!");

        caCertificateSelect = new FileChooser();
        caCertificateSelect.setTitle("Select CA Certificate");
        dataSelect = new FileChooser();
        dataSelect.setTitle("Select File to be sent");
        ipAddressSelect = new TextField("Ip address");

        clientCertificateButton.setOnAction(e -> {
            File clientCertificateFile = caCertificateSelect.showOpenDialog(window);
        });


        clientBackButton.setOnAction(e -> window.setScene(mainMenu));
        ipAddressSelect.textProperty().addListener(new ChangeListener<String>() {
            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                clientArguments[2] = newValue;
            }
        });

        clientCertificateButton.setOnAction(e -> {
            File clientCertificate = caCertificateSelect.showOpenDialog(window);
            clientArguments[0] = clientCertificate.getAbsolutePath();
            System.out.println(clientArguments[0]);
        });
        clientDataButton.setOnAction(e -> {
            File clientData = dataSelect.showOpenDialog(window);
            clientArguments[1] = clientData.getAbsolutePath();
            System.out.println(clientArguments[1]);
        });



        clientStartButton.setOnAction(e -> {

            Task clientBackgroundTask = new Task() {
                @Override
                protected Object call() throws Exception {
                    return null;
                }

                @Override
                public void run(){
                    ClientCP2 clientCP2 = new ClientCP2();


                    try {
                        clientCP2.main(clientArguments);
                        setClientDone();

                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }
                }
            };
            executorService.submit(clientBackgroundTask);

            window.setScene(clientOperation);


        });

        VBox clientMenuLayout = new VBox(20);
        clientMenuLayout.getChildren().addAll(ipAddressSelect, clientCertificateButton, clientDataButton, clientStartButton, clientBackButton);

        clientMenu = new Scene(clientMenuLayout, 500, 400);

        /**
         * Setup for serverOperation Scene
         */

        InetAddress ipAddr = InetAddress.getLocalHost();
        serverIPAddress = new Label(ipAddr.getHostAddress());

        serverQuitButton = new Button("Quit Application");
        list = new ListView<String>();
        File currentDirectory = new File(System.getProperty("user.dir"));
        File[] filesListing = currentDirectory.listFiles();
        String filesString = Arrays.toString(filesListing);
        ObservableList<String> items =FXCollections.observableArrayList ();
        for (int i = 0; i < filesListing.length; i++) {
            items.add(filesListing[i].getName());
        }
        list.setItems(items);

        try{
        updateList(e -> {});}
        catch (Exception e){
            System.out.println();
        }

        serverQuitButton.setOnAction(e -> {
            executorService.shutdown();
            try {
                executorService.awaitTermination(1, TimeUnit.SECONDS); // wait for 10s in this case
            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
            executorService.shutdownNow();

            window.close();
            Platform.exit();
            System.exit(0);
        });


        VBox serverOperationLayout = new VBox(20);
        serverOperationLayout.getChildren().addAll(serverIPAddress, list,serverQuitButton);

        serverOperation = new Scene(serverOperationLayout, 500, 400);

        /**
         * Setup for clientOperation Scene
         */

        clientStatus = new Label("File Uploading...");
        clientQuitButton = new Button("Quit Application");



        clientQuitButton.setOnAction(e -> {
            executorService.shutdown();
            try {
                executorService.awaitTermination(1, TimeUnit.SECONDS); // wait for 10s in this case
            } catch (InterruptedException e1) {
                e1.printStackTrace();
            }
            executorService.shutdownNow();

            window.close();
            Platform.exit();
            System.exit(0);
        });


        VBox clientOperationLayout = new VBox(20);
        clientOperationLayout.getChildren().addAll(clientStatus, clientQuitButton);

        clientOperation = new Scene(clientOperationLayout, 500, 400);

        File css = new File("/Users/jonathanbeiqiyang/IdeaProjects/NS_GUI/src/sample/style.css");
        mainMenu.getStylesheets().clear();
        mainMenu.getStylesheets().add("file:///" + css.getAbsolutePath().replace("\\", "/"));
        serverMenu.getStylesheets().clear();
        serverMenu.getStylesheets().add("file:///" + css.getAbsolutePath().replace("\\", "/"));
        serverOperation.getStylesheets().clear();
        serverOperation.getStylesheets().add("file:///" + css.getAbsolutePath().replace("\\", "/"));
        clientMenu.getStylesheets().clear();
        clientMenu.getStylesheets().add("file:///" + css.getAbsolutePath().replace("\\", "/"));
        clientOperation.getStylesheets().clear();
        clientOperation.getStylesheets().add("file:///" + css.getAbsolutePath().replace("\\", "/"));

        window.setScene(mainMenu);
        window.setTitle("NS Menu");
        window.show();

    }

    private void updateList(EventHandler<ActionEvent> e){
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(updateListTask,0,100);

    }

    class UpdateListTask extends TimerTask{

        @Override
        public void run() {
            Platform.runLater(() -> {
                File currentDirectory = new File(System.getProperty("user.dir"));
                File[] filesListing = currentDirectory.listFiles();
                String filesString = Arrays.toString(filesListing);
                ObservableList<String> items =FXCollections.observableArrayList ();
                for (int i = 0; i < filesListing.length; i++) {
                    items.add(filesListing[i].getName());
                }
                list.setItems(items);
                list.refresh();
            });

        }
    }



    public void setClientDone () {

        Platform.runLater(() -> {
            clientStatus.textProperty().setValue("File Uploaded Successfully!");
        });

    }





    public static void main(String[] args) {
        launch(args);
    }
}
