package co.gov.cajaviviendapopular.inventoryservice.controller;

import co.gov.cajaviviendapopular.inventoryservice.model.Purchase;
import co.gov.cajaviviendapopular.inventoryservice.service.PurchaseService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/purchases")
public class PurchaseController {

    protected PurchaseService purchaseService;

    public PurchaseController(PurchaseService purchaseService) {
        this.purchaseService = purchaseService;
    }

    @PostMapping
    public ResponseEntity<Purchase> newPurchase(@RequestBody Purchase purchase) {
        return ResponseEntity.ok(this.purchaseService.createNewPurchase(purchase));
    }

    @GetMapping
    public ResponseEntity<List<Purchase>> getAllPurchases() {
        return ResponseEntity.ok(this.purchaseService.getAll());
    }
}