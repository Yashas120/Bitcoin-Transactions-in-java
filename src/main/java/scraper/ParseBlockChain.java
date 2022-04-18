package scraper;

import java.io.IOException;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.json.JSONArray;
import org.json.JSONObject;

public class ParseBlockChain {

  public void get() {

    Document doc;
    try {

        doc = Jsoup.connect("https://www.blockchain.com/btc-testnet/address/mnNcaVkC35ezZSgvn8fhXEa9QTHSUtPfzQ").get();

        // get title of the page
        String title = doc.title();
        System.out.println("Title: " + title);

        // get main dashboard
        Elements links = doc.select("div[class=sc-1enh6xt-0 kiseLw]");
        for (Element link : links) {

            // get the value from href attribute
            System.out.println("\nLink : " + link.attr("class"));
            System.out.println("Text : " + link.text());
        }

        Elements script = doc.select("script#__NEXT_DATA__");
        for (Element link : script) {

            JSONObject n = new JSONObject(link.data());
            JSONObject n1 = new JSONObject(n.get("props").toString());
            JSONObject n2 = new JSONObject(n1.get("initialProps").toString());
            JSONObject n3 = new JSONObject(n2.get("pageProps").toString());
            JSONArray n4 = new JSONArray(n3.get("addressTransactions").toString());
            System.out.println(n4.get(0));
        }


    } catch (IOException e) {
        e.printStackTrace();
    }

  }

}
