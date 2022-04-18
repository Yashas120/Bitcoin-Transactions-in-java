package get;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.io.IOException;

public class EntityAsString {
    public void get() {
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet("https://www.blockchain.com/btc-testnet/address/mnNcaVkC35ezZSgvn8fhXEa9QTHSUtPfzQ");

        try {
            HttpResponse response = client.execute(request);
            HttpEntity entity = response.getEntity();

            // Read the contents of an entity and return it as a String.
            String content = EntityUtils.toString(entity);
            JSONObject obj = new JSONObject(content);
            System.out.println(obj);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
